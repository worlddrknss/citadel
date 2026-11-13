package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

func TestAgentAnomalies(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	rt := e.s.agentAnomalyRT()
	rt.sync = true
	now := time.Date(2026, 11, 13, 3, 30, 0, 0, time.UTC)
	rt.now = func() time.Time { return now }

	id := e.agentCreate(bob, "watched")
	tok := e.agentToken(bob, id, 1)
	ctx := context.Background()
	list := func() []store.AgentAnomaly {
		t.Helper()
		l, err := e.st.ListAgentAnomalies(ctx, e.acctA, id, 50)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	// Repeated denials, end to end: ten refused brokered calls in ten
	// minutes raise one anomaly (not one per further denial).
	for i := 0; i < 12; i++ {
		wantStatus(t, e.do(http.MethodPost, "/v1/agent/http", map[string]any{"credential": "nope", "url": "https://api.example.com/"}, nil, bearer(tok)), http.StatusForbidden)
	}
	if l := list(); len(l) != 1 || l[0].Kind != store.AgentAnomalyRepeatedDenials {
		t.Fatalf("anomalies after denials = %+v", l)
	}
	if !e.audited(auditAgentAnomaly, store.AuditResultSuccess) {
		t.Fatal("anomaly not audited")
	}

	// With an established baseline (hosts, working hours 09-17 UTC, ~4 uses
	// an hour): a new host and use at 03:00 are anomalies, a known host in
	// working hours is not.
	key := e.acctA + "\x00" + id
	base := &agentBaseline{hosts: map[string]bool{"api.github.com": true}, events: 400, activeHours: 100, first: now.Add(-10 * 24 * time.Hour), loadedAt: now}
	for h := 9; h < 17; h++ {
		base.hours[h] = 50
	}
	rt.mu.Lock()
	rt.agents[key].baseline = base
	rt.mu.Unlock()
	use := func(host string) {
		e.s.observeAgentEvent(store.AuditEvent{Action: actionAgentHTTP, Result: store.AuditResultSuccess, AuditOrigin: store.AuditOrigin{
			AccountID: e.acctA, ActorType: store.AuditActorAgent, AgentID: id, Resource: "credential=x method=GET host=" + host + " path=/ status=200 via=api"}})
	}
	use("api.github.com")
	kinds := map[string]bool{}
	for _, a := range list() {
		kinds[a.Kind] = true
	}
	if !kinds[store.AgentAnomalyOffHours] || kinds[store.AgentAnomalyNewHost] {
		t.Fatalf("after off-hours use: %v", kinds)
	}
	now = now.Add(7 * time.Hour) // 10:30, working hours
	use("exfil.example.net")
	use("exfil.example.net")
	n := 0
	for _, a := range list() {
		if a.Kind == store.AgentAnomalyNewHost {
			n++
			if !strings.Contains(a.Detail, "exfil.example.net") {
				t.Fatalf("detail %q", a.Detail)
			}
		}
		if a.Kind == store.AgentAnomalyOffHours && a.Hour.Hour() == 10 {
			t.Fatal("working-hours use flagged as off-hours")
		}
	}
	if n != 1 {
		t.Fatalf("new_host anomalies = %d", n)
	}

	// Auto-suspend (off by default) suspends through the normal path on the
	// next anomaly: a rate spike well above the usual 4 an hour.
	wantStatus(t, e.do(http.MethodPost, "/v1/agents/anomaly-settings", map[string]any{"agentId": id, "autoSuspend": true}, e.session("carol", e.acctB)), http.StatusForbidden)
	rec := e.do(http.MethodPost, "/v1/agents/anomaly-settings", map[string]any{"agentId": id, "autoSuspend": true, "alertsEnabled": true}, bob)
	wantStatus(t, rec, http.StatusOK)
	if got := decode(t, rec); got["autoSuspend"] != true || got["alertsEnabled"] != true {
		t.Fatalf("settings = %v", got)
	}
	for i := 0; i < 25; i++ {
		use("api.github.com")
	}
	a, err := e.st.GetAgent(ctx, e.acctA, id)
	if err != nil || a.Status != store.AgentStatusSuspended || a.StatusChangedBy != agentAnomalyActor {
		t.Fatalf("agent after spike = %+v, %v", a, err)
	}
	var spikeSuspended, suspendAudited bool
	for _, an := range list() {
		spikeSuspended = spikeSuspended || an.Kind == store.AgentAnomalyRateSpike && an.Suspended
	}
	for _, ev := range e.agentEvents(e.acctA, id) {
		suspendAudited = suspendAudited || ev.Action == auditSuspendAgent && ev.Actor == agentAnomalyActor && ev.ActorType == store.AuditActorSystem
	}
	if !spikeSuspended || !suspendAudited {
		t.Fatalf("spike suspended=%v audited=%v", spikeSuspended, suspendAudited)
	}

	// The console lists anomalies, settings and the baseline.
	rec = e.do(http.MethodGet, "/v1/agents/anomalies?agentId="+id, nil, bob)
	wantStatus(t, rec, http.StatusOK)
	got := decode(t, rec)
	if len(got["anomalies"].([]any)) != 4 || got["settings"].(map[string]any)["autoSuspend"] != true || got["baseline"] == nil {
		t.Fatalf("GET anomalies = %v", got)
	}
	wantStatus(t, e.do(http.MethodGet, "/v1/agents/anomalies?agentId="+id, nil, e.session("bob", e.acctB)), http.StatusNotFound)
}

func TestAgentBaselineFromAudit(t *testing.T) {
	e := newAuthEnv(t)
	bob := e.session("bob", e.acctA)
	id := e.agentCreate(bob, "learner")
	ctx := store.WithCallerAccount(context.Background(), e.acctA)
	for i := 0; i < 3; i++ {
		_ = e.st.RecordAudit(ctx, store.AuditEvent{Action: actionAgentHTTP, Result: store.AuditResultSuccess, AuditOrigin: store.AuditOrigin{
			AccountID: e.acctA, ActorType: store.AuditActorAgent, AgentID: id, Resource: "credential=x method=GET host=api.example.com path=/ via=api"}})
	}
	_ = e.st.RecordAudit(ctx, store.AuditEvent{Action: actionAgentHTTP, Result: store.AuditResultDenied, AuditOrigin: store.AuditOrigin{
		AccountID: e.acctA, ActorType: store.AuditActorAgent, AgentID: id, Resource: "credential=x host=denied.example.com via=api"}})
	b, err := e.s.loadAgentBaseline(context.Background(), e.acctA, id, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if b.events != 3 || !b.hosts["api.example.com"] || b.hosts["denied.example.com"] || b.activeHours != 1 || b.established() {
		t.Fatalf("baseline = %+v", b)
	}
}
