package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Agent anomaly alerts (2.4).
//
// Each replica keeps, per agent, a baseline learned from the agent's audit
// events of the last 14 days (the hosts it reached, the UTC hours of day it
// works, its hourly rate), refreshed hourly in the background, and counts
// its recent calls and denials. Every agent audit event of a credential use
// (brokered HTTP, reveal, TOTP, get_login) and every denial is checked
// against it in memory:
//
//   - new_host: a host the agent never reached in its baseline;
//   - off_hours: use in an hour of day the agent was never active in;
//   - rate_spike: more than 5x its usual hourly rate and more than 20 in
//     the last hour;
//   - repeated_denials: 10 or more refusals in 10 minutes.
//
// new_host and off_hours need an established baseline (at least 20 uses
// over more than two days). An anomaly is recorded once per kind, agent and
// hour (the store's unique key de-duplicates across replicas), audited as
// citadel.AgentAnomaly, sent to the notification channels as agent.anomaly
// unless the agent's alerts are off, and suspends the agent when it has
// auto-suspend on.

const (
	auditAgentAnomaly               = "citadel.AgentAnomaly"
	auditPutAgentAnomalySettings    = "citadel.PutAgentAnomalySettings"
	agentAnomalyActor               = "anomaly-detector"
	agentBaselineWindow             = 14 * 24 * time.Hour
	agentBaselineRefresh            = time.Hour
	agentBaselinePageSize           = 5000
	agentBaselineMaxPages           = 4
	agentBaselineMinEvents          = 20
	agentBaselineMinSpan            = 48 * time.Hour
	agentRateSpikeFactor            = 5
	agentRateSpikeMin               = 20
	agentDenialWindow               = 10 * time.Minute
	agentDenialThreshold            = 10
	agentAnomalyMaxTracked          = 10000
	agentAnomalyMaxRecentPerAgent   = 5000
	agentAnomalyBaselineLoadTimeout = 30 * time.Second
)

// agentUsageActions are the audit actions that count as using a credential.
var agentUsageActions = map[string]bool{
	actionAgentHTTP: true, actionAgentReveal: true, actionAgentTOTP: true, actionAgentGetLogin: true,
}

// agentBaseline is what an agent usually does.
type agentBaseline struct {
	hosts  map[string]bool
	hours  [24]int
	events int
	// activeHours is the number of distinct clock hours with any use.
	activeHours int
	first       time.Time
	loadedAt    time.Time
}

func (b *agentBaseline) established() bool {
	return b != nil && b.events >= agentBaselineMinEvents && b.loadedAt.Sub(b.first) > agentBaselineMinSpan
}

// meanPerActiveHour is the usual number of uses in an hour the agent works.
func (b *agentBaseline) meanPerActiveHour() float64 {
	if b == nil || b.activeHours == 0 {
		return 0
	}
	return float64(b.events) / float64(b.activeHours)
}

type agentAnomalyState struct {
	baseline *agentBaseline
	loading  bool
	uses     []time.Time          // successful uses in the last hour
	denials  []time.Time          // denials in the last agentDenialWindow
	raised   map[string]time.Time // kind -> hour last raised by this replica
}

type agentAnomalyRuntime struct {
	mu     sync.Mutex
	agents map[string]*agentAnomalyState // account\x00agent
	now    func() time.Time
	// sync runs raise inline (tests); otherwise in a goroutine.
	sync bool
	wg   sync.WaitGroup
}

var agentAnomalyRuntimes sync.Map // *Server -> *agentAnomalyRuntime

func (s *Server) agentAnomalyRT() *agentAnomalyRuntime {
	if v, ok := agentAnomalyRuntimes.Load(s); ok {
		return v.(*agentAnomalyRuntime)
	}
	v, _ := agentAnomalyRuntimes.LoadOrStore(s, &agentAnomalyRuntime{agents: map[string]*agentAnomalyState{}, now: time.Now})
	return v.(*agentAnomalyRuntime)
}

// auditResourceField returns key's value in a "k=v k2=v2" audit resource.
func auditResourceField(resource, key string) string {
	for _, f := range strings.Fields(resource) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

// observeAgentEvent checks an audit event an agent caused against its
// baseline. It never blocks on the store: baselines load and anomalies are
// raised in the background.
func (s *Server) observeAgentEvent(ev store.AuditEvent) {
	if ev.ActorType != store.AuditActorAgent || ev.AgentID == "" || ev.AccountID == "" {
		return
	}
	result := store.NormalizeAuditResult(ev.Result, ev.ErrorType)
	denied := result == store.AuditResultDenied
	usage := agentUsageActions[ev.Action] && result == store.AuditResultSuccess
	if !denied && !usage {
		return
	}
	rt := s.agentAnomalyRT()
	now := rt.now().UTC()
	key := ev.AccountID + "\x00" + ev.AgentID
	type raise struct{ kind, detail string }
	var raises []raise
	load := false

	rt.mu.Lock()
	st := rt.agents[key]
	if st == nil {
		if len(rt.agents) >= agentAnomalyMaxTracked {
			rt.agents = map[string]*agentAnomalyState{}
		}
		st = &agentAnomalyState{raised: map[string]time.Time{}}
		rt.agents[key] = st
	}
	hour := now.Truncate(time.Hour)
	add := func(kind, detail string) {
		if st.raised[kind].Equal(hour) {
			return
		}
		st.raised[kind] = hour
		raises = append(raises, raise{kind, detail})
	}
	if denied {
		st.denials = append(pruneBefore(st.denials, now.Add(-agentDenialWindow)), now)
		if len(st.denials) >= agentDenialThreshold {
			add(store.AgentAnomalyRepeatedDenials, fmt.Sprintf("%d refused requests in 10 minutes", len(st.denials)))
		}
	}
	if usage {
		st.uses = pruneBefore(st.uses, now.Add(-time.Hour))
		if len(st.uses) < agentAnomalyMaxRecentPerAgent {
			st.uses = append(st.uses, now)
		}
		b := st.baseline
		if (b == nil || now.Sub(b.loadedAt) > agentBaselineRefresh) && !st.loading {
			st.loading, load = true, true
		}
		if b != nil {
			if mean := b.meanPerActiveHour(); len(st.uses) > agentRateSpikeMin && float64(len(st.uses)) > agentRateSpikeFactor*mean {
				add(store.AgentAnomalyRateSpike, fmt.Sprintf("%d uses in the last hour (usually %.1f an hour)", len(st.uses), mean))
			}
			if b.established() {
				if host := auditResourceField(ev.Resource, "host"); host != "" && !b.hosts[host] {
					b.hosts[host] = true
					add(store.AgentAnomalyNewHost, "first use of host "+host)
				}
				if b.hours[now.Hour()] == 0 {
					add(store.AgentAnomalyOffHours, fmt.Sprintf("use at %02d:00 UTC, an hour this agent has not worked in", now.Hour()))
				}
			}
		}
	}
	rt.mu.Unlock()

	run := func(f func()) {
		if rt.sync {
			f()
			return
		}
		rt.wg.Add(1)
		go func() { defer rt.wg.Done(); f() }()
	}
	if load {
		run(func() { s.refreshAgentBaseline(ev.AccountID, ev.AgentID) })
	}
	for _, r := range raises {
		run(func() { s.raiseAgentAnomaly(ev.AccountID, ev.AgentID, r.kind, r.detail, now) })
	}
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}

// loadAgentBaseline learns an agent's baseline from its audit events of the
// last 14 days (at most 20,000 of the most recent).
func (s *Server) loadAgentBaseline(ctx context.Context, accountID, agentID string, now time.Time) (*agentBaseline, error) {
	ctx = store.WithCallerAccount(ctx, accountID)
	from := now.Add(-agentBaselineWindow)
	b := &agentBaseline{hosts: map[string]bool{}, loadedAt: now}
	hoursSeen := map[int64]bool{}
	var before int64
	for page := 0; page < agentBaselineMaxPages; page++ {
		recs, err := s.store.QueryAuditEvents(ctx, store.AuditQuery{Agent: agentID, From: &from, Limit: agentBaselinePageSize, BeforeID: before})
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if before == 0 || r.ID < before {
				before = r.ID
			}
			if r.ActorType != store.AuditActorAgent || !agentUsageActions[r.Action] || store.NormalizeAuditResult(r.Result, r.ErrorType) != store.AuditResultSuccess {
				continue
			}
			t := r.CreatedAt.UTC()
			b.events++
			b.hours[t.Hour()]++
			hoursSeen[t.Unix()/3600] = true
			if b.first.IsZero() || t.Before(b.first) {
				b.first = t
			}
			if host := auditResourceField(r.Resource, "host"); host != "" {
				b.hosts[host] = true
			}
		}
		if len(recs) < agentBaselinePageSize {
			break
		}
	}
	b.activeHours = len(hoursSeen)
	return b, nil
}

func (s *Server) refreshAgentBaseline(accountID, agentID string) {
	rt := s.agentAnomalyRT()
	ctx, cancel := context.WithTimeout(context.Background(), agentAnomalyBaselineLoadTimeout)
	defer cancel()
	b, err := s.loadAgentBaseline(ctx, accountID, agentID, rt.now().UTC())
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.agents[accountID+"\x00"+agentID]
	if st == nil {
		return
	}
	st.loading = false
	if err != nil {
		log.Printf("agent anomalies: baseline load failed: %v", err)
		return
	}
	// Hosts first seen since the last load stay known.
	if st.baseline != nil {
		for h := range st.baseline.hosts {
			b.hosts[h] = true
		}
	}
	st.baseline = b
}

// raiseAgentAnomaly records, audits and notifies an anomaly, and suspends
// the agent when its settings say so.
func (s *Server) raiseAgentAnomaly(accountID, agentID, kind, detail string, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := s.store.GetAgent(ctx, accountID, agentID)
	if err != nil {
		if !errors.Is(err, store.ErrAgentNotFound) {
			log.Printf("agent anomalies: agent read failed: %v", err)
		}
		return
	}
	settings, err := s.store.GetAgentAnomalySettings(ctx, accountID, agentID)
	if err != nil {
		log.Printf("agent anomalies: settings read failed: %v", err)
	}
	an := store.AgentAnomaly{AccountID: accountID, AgentID: agentID, AnomalyID: store.NewAgentObjectID("aan_"), Kind: kind, Detail: detail,
		Hour: now.Truncate(time.Hour), DetectedAt: now.Truncate(time.Second)}
	if err := s.store.RecordAgentAnomaly(ctx, an); err != nil {
		if !errors.Is(err, store.ErrAgentAnomalyDuplicate) && !errors.Is(err, store.ErrAgentNotFound) {
			log.Printf("agent anomalies: record failed: %v", err)
		}
		return
	}
	origin := store.AuditOrigin{AccountID: accountID, Actor: agentAnomalyActor, ActorType: store.AuditActorSystem, AgentID: a.AgentID, AgentOwner: a.Owner,
		Resource: "kind=" + kind + " anomaly=" + an.AnomalyID}
	s.recordAudit(ctx, store.AuditEvent{Action: auditAgentAnomaly, KeyID: a.AgentID, Result: store.AuditResultSuccess, AuditOrigin: origin})

	suspend := settings.AutoSuspend && a.Status == store.AgentStatusActive
	if !settings.AlertsDisabled {
		payload := map[string]any{
			"agentId": a.AgentID, "name": a.Name, "owner": a.Owner, "kind": kind, "detail": detail, "anomalyId": an.AnomalyID,
			"autoSuspend": suspend, "summary": a.Name + ": " + agentAnomalyTitle(kind) + " (" + detail + ")",
		}
		if err := s.notify(ctx, accountID, EventAgentAnomaly, payload); err != nil {
			log.Printf("agent anomalies: notify failed: %v", err)
		}
	}
	if suspend {
		s.autoSuspendAgent(ctx, a, an)
	}
}

func agentAnomalyTitle(kind string) string {
	switch kind {
	case store.AgentAnomalyNewHost:
		return "new host"
	case store.AgentAnomalyOffHours:
		return "off-hours use"
	case store.AgentAnomalyRateSpike:
		return "rate spike"
	case store.AgentAnomalyRepeatedDenials:
		return "repeated denials"
	}
	return kind
}

// autoSuspendAgent suspends an agent after an anomaly, as a console suspend
// does (status change, audit, leases ended, agent.suspended notification),
// with the anomaly detector as the actor.
func (s *Server) autoSuspendAgent(ctx context.Context, a store.Agent, an store.AgentAnomaly) {
	reason := "anomaly: " + agentAnomalyTitle(an.Kind)
	updated, err := s.store.SetAgentStatus(ctx, a.AccountID, a.AgentID, store.AgentStatusSuspended, agentAnomalyActor, reason, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		log.Printf("agent anomalies: auto-suspend failed: %v", err)
		return
	}
	origin := store.AuditOrigin{AccountID: a.AccountID, Actor: agentAnomalyActor, ActorType: store.AuditActorSystem, AgentID: a.AgentID, AgentOwner: a.Owner,
		Resource: a.AgentID + " anomaly=" + an.AnomalyID}
	s.recordAudit(ctx, store.AuditEvent{Action: auditSuspendAgent, KeyID: a.AgentID, Result: store.AuditResultSuccess, AuditOrigin: origin})
	if err := s.store.MarkAgentAnomalySuspended(ctx, a.AccountID, an.AnomalyID); err != nil {
		log.Printf("agent anomalies: mark suspended failed: %v", err)
	}
	if n, err := s.store.EndAgentLeases(ctx, a.AccountID, a.AgentID, agentAnomalyActor, "agent suspended", time.Now().UTC().Truncate(time.Second)); err != nil {
		log.Printf("agent anomalies: end leases failed: %v", err)
	} else if n > 0 {
		o := origin
		o.Resource = "leases=" + strconv.Itoa(n) + " reason=agent suspended"
		s.recordAudit(ctx, store.AuditEvent{Action: auditRevokeAgentLease, KeyID: a.AgentID, Result: store.AuditResultSuccess, AuditOrigin: o})
	}
	payload := map[string]any{"agentId": updated.AgentID, "name": updated.Name, "owner": updated.Owner, "actor": agentAnomalyActor, "reason": reason,
		"summary": updated.Name + " was suspended automatically after an anomaly (" + agentAnomalyTitle(an.Kind) + ")"}
	if err := s.notify(ctx, a.AccountID, EventAgentSuspended, payload); err != nil {
		log.Printf("agent anomalies: notify failed: %v", err)
	}
}

// ---- console ------------------------------------------------------------------

type agentAnomalyJSON struct {
	AnomalyID  string `json:"anomalyId"`
	Kind       string `json:"kind"`
	Detail     string `json:"detail"`
	DetectedAt string `json:"detectedAt"`
	Suspended  bool   `json:"suspended"`
}

type agentAnomalySettingsJSON struct {
	AlertsEnabled bool   `json:"alertsEnabled"`
	AutoSuspend   bool   `json:"autoSuspend"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
	UpdatedBy     string `json:"updatedBy,omitempty"`
}

func anomalySettingsOut(st store.AgentAnomalySettings) agentAnomalySettingsJSON {
	out := agentAnomalySettingsJSON{AlertsEnabled: !st.AlertsDisabled, AutoSuspend: st.AutoSuspend, UpdatedBy: st.UpdatedBy}
	if !st.UpdatedAt.IsZero() {
		out.UpdatedAt = fmtTime(st.UpdatedAt)
	}
	return out
}

type agentBaselineJSON struct {
	// Established: enough history (20 uses over more than two days) for
	// new-host and off-hours alerts.
	Established bool     `json:"established"`
	Events      int      `json:"events"`
	Hosts       []string `json:"hosts"`
	// ActiveHours are the UTC hours of day the agent has worked in.
	ActiveHours   []int   `json:"activeHours"`
	MeanPerHour   float64 `json:"meanPerHour"`
	WindowDays    int     `json:"windowDays"`
	RateSpikeMin  int     `json:"rateSpikeMin"`
	RateSpikeX    int     `json:"rateSpikeFactor"`
	DenialsWindow int     `json:"denialsWindowMinutes"`
	DenialsMin    int     `json:"denialsThreshold"`
}

// handleV1AgentAnomalies is GET /v1/agents/anomalies?agentId=: the agent's
// anomalies, its alert settings and its current baseline.
func (s *Server) handleV1AgentAnomalies(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "viewer")
	if !ok {
		return
	}
	agentID := strings.TrimSpace(r.URL.Query().Get("agentId"))
	if !store.IsAgentID(agentID) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "agentId is required")
		return
	}
	acct := s.agentAccount(ctx, sess)
	a, err := s.store.GetAgent(ctx, acct, agentID)
	if errors.Is(err, store.ErrAgentNotFound) {
		writeNativeError(w, http.StatusNotFound, "not_found", "agent not found")
		return
	}
	var (
		list     []store.AgentAnomaly
		settings store.AgentAnomalySettings
		base     *agentBaseline
	)
	if err == nil {
		list, err = s.store.ListAgentAnomalies(ctx, acct, agentID, 100)
	}
	if err == nil {
		settings, err = s.store.GetAgentAnomalySettings(ctx, acct, agentID)
	}
	if err == nil {
		base, err = s.loadAgentBaseline(ctx, acct, agentID, time.Now().UTC())
	}
	if err != nil {
		log.Printf("agents: anomalies read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not read the agent's anomalies")
		return
	}
	out := make([]agentAnomalyJSON, 0, len(list))
	for _, an := range list {
		out = append(out, agentAnomalyJSON{AnomalyID: an.AnomalyID, Kind: an.Kind, Detail: an.Detail, DetectedAt: fmtTime(an.DetectedAt), Suspended: an.Suspended})
	}
	bj := agentBaselineJSON{Established: base.established(), Events: base.events, Hosts: []string{}, ActiveHours: []int{}, MeanPerHour: base.meanPerActiveHour(),
		WindowDays: int(agentBaselineWindow / (24 * time.Hour)), RateSpikeMin: agentRateSpikeMin, RateSpikeX: agentRateSpikeFactor,
		DenialsWindow: int(agentDenialWindow / time.Minute), DenialsMin: agentDenialThreshold}
	for h := range base.hosts {
		bj.Hosts = append(bj.Hosts, h)
	}
	sort.Strings(bj.Hosts)
	for h, n := range base.hours {
		if n > 0 {
			bj.ActiveHours = append(bj.ActiveHours, h)
		}
	}
	writeNativeJSON(w, http.StatusOK, map[string]any{
		"anomalies": out, "settings": anomalySettingsOut(settings), "baseline": bj, "canManage": canManageAgent(sess, a),
	})
}

type agentAnomalySettingsInput struct {
	AgentID       string `json:"agentId"`
	AlertsEnabled *bool  `json:"alertsEnabled"`
	AutoSuspend   *bool  `json:"autoSuspend"`
}

// handleV1PutAgentAnomalySettings is POST /v1/agents/anomaly-settings.
func (s *Server) handleV1PutAgentAnomalySettings(w http.ResponseWriter, r *http.Request) {
	sess, ctx, ok := s.nativeSession(w, r, "editor")
	if !ok {
		return
	}
	var in agentAnomalySettingsInput
	if err := decodeJSONBody(r, &in); err != nil {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}
	a, ok := s.loadManagedAgent(w, r, ctx, sess, strings.TrimSpace(in.AgentID), auditPutAgentAnomalySettings)
	if !ok {
		return
	}
	st, err := s.store.GetAgentAnomalySettings(ctx, a.AccountID, a.AgentID)
	if err != nil {
		log.Printf("agents: anomaly settings read failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "internal_error", "could not save the settings")
		return
	}
	if in.AlertsEnabled != nil {
		st.AlertsDisabled = !*in.AlertsEnabled
	}
	if in.AutoSuspend != nil {
		st.AutoSuspend = *in.AutoSuspend
	}
	st.AccountID, st.AgentID, st.UpdatedAt, st.UpdatedBy = a.AccountID, a.AgentID, time.Now().UTC().Truncate(time.Second), sess.Principal()
	if err := s.store.PutAgentAnomalySettings(ctx, st); err != nil {
		log.Printf("agents: anomaly settings save failed: %v", err)
		writeNativeError(w, http.StatusInternalServerError, "save_failed", "could not save the settings")
		return
	}
	o := s.agentOrigin(r, a)
	o.Resource = fmt.Sprintf("%s alerts=%t autoSuspend=%t", a.AgentID, !st.AlertsDisabled, st.AutoSuspend)
	s.recordAudit(ctx, store.AuditEvent{Action: auditPutAgentAnomalySettings, KeyID: a.AgentID, Result: "ok", AuditOrigin: o})
	writeNativeJSON(w, http.StatusOK, anomalySettingsOut(st))
}
