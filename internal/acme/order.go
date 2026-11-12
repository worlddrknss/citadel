package acme

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type orderJSON struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *Problem     `json:"error,omitempty"`
}

func (s *Server) orderJSON(o *Order) orderJSON {
	j := orderJSON{
		Status:         o.Status,
		Expires:        rfc3339(o.Expires),
		Identifiers:    o.Identifiers,
		Authorizations: make([]string, 0, len(o.AuthzIDs)),
		Finalize:       s.url(pathOrder + o.ID + "/finalize"),
		Error:          o.Error,
	}
	if !o.NotAfter.IsZero() {
		j.NotAfter = rfc3339(o.NotAfter)
	}
	for _, id := range o.AuthzIDs {
		j.Authorizations = append(j.Authorizations, s.url(pathAuthz+id))
	}
	if o.CertificateID != "" {
		j.Certificate = s.url(pathCert + o.CertificateID)
	}
	return j
}

type challengeJSON struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Status    string   `json:"status"`
	Token     string   `json:"token"`
	Validated string   `json:"validated,omitempty"`
	Error     *Problem `json:"error,omitempty"`
}

type authzJSON struct {
	Identifier Identifier      `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires"`
	Challenges []challengeJSON `json:"challenges"`
	Wildcard   bool            `json:"wildcard,omitempty"`
}

func (s *Server) challengeJSON(az *Authorization, c *Challenge) challengeJSON {
	j := challengeJSON{
		Type:   c.Type,
		URL:    s.url(pathChall + az.ID + "/" + c.ID),
		Status: c.Status,
		Token:  c.Token,
		Error:  c.Error,
	}
	if !c.Validated.IsZero() {
		j.Validated = rfc3339(c.Validated)
	}
	return j
}

func (s *Server) authzJSON(az *Authorization) authzJSON {
	j := authzJSON{
		Identifier: az.Identifier,
		Status:     az.Status,
		Expires:    rfc3339(az.Expires),
		Wildcard:   az.Wildcard,
		Challenges: make([]challengeJSON, 0, len(az.Challenges)),
	}
	for i := range az.Challenges {
		j.Challenges = append(j.Challenges, s.challengeJSON(az, &az.Challenges[i]))
	}
	return j
}

// handleNewOrder implements RFC 8555 §7.4.
func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request, rel string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	var p struct {
		Identifiers []Identifier `json:"identifiers"`
		NotBefore   string       `json:"notBefore"`
		NotAfter    string       `json:"notAfter"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	if len(p.Identifiers) == 0 {
		s.problem(w, malformed("order must contain at least one identifier"))
		return
	}
	if len(p.Identifiers) > s.cfg.MaxIdentifiers {
		s.problem(w, newProblem(ProbRejectedIdentifier, http.StatusBadRequest, "order has more than %d identifiers", s.cfg.MaxIdentifiers))
		return
	}
	if p.NotBefore != "" {
		s.problem(w, malformed("notBefore is not supported"))
		return
	}
	now := s.now()
	var notAfter time.Time
	if p.NotAfter != "" {
		t, err := time.Parse(time.RFC3339, p.NotAfter)
		if err != nil {
			s.problem(w, malformed("notAfter is not an RFC 3339 timestamp"))
			return
		}
		if !t.After(now) || t.Sub(now) > s.cfg.MaxCertLifetime {
			s.problem(w, malformed("notAfter must be in the future and at most %s away", s.cfg.MaxCertLifetime))
			return
		}
		notAfter = t.UTC()
	}

	ctx := r.Context()
	acct := req.account
	seen := map[Identifier]bool{}
	var ids []Identifier
	var subs []Problem
	for _, raw := range p.Identifiers {
		id, prob := normalizeIdentifier(raw)
		if prob != nil {
			subs = append(subs, *prob)
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if err := s.cfg.Policy.Allow(ctx, acct.AccountRef, id); err != nil {
			sp := asProblem(err, ProbRejectedIdentifier, http.StatusBadRequest, "identifier is not allowed by policy")
			if sp.Identifier == nil {
				sp.Identifier = &id
			}
			subs = append(subs, *sp)
			continue
		}
		ids = append(ids, id)
	}
	if len(subs) > 0 {
		top := subs[0]
		if len(subs) > 1 {
			top = Problem{Type: ProbRejectedIdentifier, Status: http.StatusBadRequest, Detail: "some identifiers were rejected", Subproblems: subs}
		}
		top.Status = statusFor(top.Type)
		s.problem(w, &top)
		return
	}

	n, err := s.store.CountPendingOrders(ctx, acct.ID, now)
	if err != nil {
		s.problem(w, s.internal("counting orders", err))
		return
	}
	if n >= s.cfg.MaxPendingOrders {
		s.problem(w, newProblem(ProbRateLimited, http.StatusTooManyRequests, "too many pending orders"))
		return
	}

	expires := now.Add(s.cfg.OrderLifetime).UTC().Truncate(time.Second)
	order := &Order{
		ID:          randomID(12),
		AccountID:   acct.ID,
		Status:      StatusPending,
		Identifiers: ids,
		Expires:     expires,
		NotAfter:    notAfter,
		CreatedAt:   now.UTC(),
	}
	authzs := make([]*Authorization, 0, len(ids))
	for _, id := range ids {
		az := &Authorization{
			ID:        randomID(12),
			AccountID: acct.ID,
			Status:    StatusPending,
			Expires:   expires,
		}
		var types []string
		switch {
		case id.Type == IdentifierIP:
			az.Identifier = id
			types = []string{ChallengeHTTP01}
		case strings.HasPrefix(id.Value, "*."):
			az.Identifier = Identifier{Type: IdentifierDNS, Value: strings.TrimPrefix(id.Value, "*.")}
			az.Wildcard = true
			types = []string{ChallengeDNS01}
		default:
			az.Identifier = id
			types = []string{ChallengeHTTP01, ChallengeDNS01}
		}
		for _, t := range types {
			az.Challenges = append(az.Challenges, Challenge{
				ID:     randomID(8),
				Type:   t,
				Token:  randomID(32),
				Status: StatusPending,
			})
		}
		authzs = append(authzs, az)
		order.AuthzIDs = append(order.AuthzIDs, az.ID)
	}
	if err := s.store.CreateOrder(ctx, order, authzs); err != nil {
		s.problem(w, s.internal("creating order", err))
		return
	}
	w.Header().Set("Location", s.url(pathOrder+order.ID))
	s.writeJSON(w, http.StatusCreated, s.orderJSON(order))
}

// refreshAuthz expires a pending or valid authorization past its expiry.
func (s *Server) refreshAuthz(ctx context.Context, az *Authorization) error {
	for range 5 {
		if (az.Status != StatusPending && az.Status != StatusValid) || s.now().Before(az.Expires) {
			return nil
		}
		az.Status = StatusExpired
		err := s.store.UpdateAuthorization(ctx, az)
		if !errors.Is(err, ErrStale) {
			return err
		}
		fresh, err := s.store.GetAuthorization(ctx, az.ID)
		if err != nil {
			return err
		}
		*az = *fresh
	}
	return ErrStale
}

// refreshOrder recomputes a pending or ready order's status from its
// authorizations and expiry (RFC 8555 §7.1.6) and persists any change.
func (s *Server) refreshOrder(ctx context.Context, o *Order) error {
	for range 5 {
		if o.Status != StatusPending && o.Status != StatusReady {
			return nil
		}
		next := StatusReady
		if !s.now().Before(o.Expires) {
			next = StatusInvalid
		} else {
			for _, id := range o.AuthzIDs {
				az, err := s.store.GetAuthorization(ctx, id)
				if err != nil {
					return err
				}
				if err := s.refreshAuthz(ctx, az); err != nil {
					return err
				}
				switch az.Status {
				case StatusValid:
				case StatusPending:
					if next == StatusReady {
						next = StatusPending
					}
				default:
					next = StatusInvalid
				}
				if next == StatusInvalid {
					break
				}
			}
		}
		if next == o.Status {
			return nil
		}
		o.Status = next
		if next == StatusInvalid && o.Error == nil {
			o.Error = unauthorized("an authorization for this order is not valid, or the order expired")
		}
		err := s.store.UpdateOrder(ctx, o)
		if !errors.Is(err, ErrStale) {
			return err
		}
		fresh, err := s.store.GetOrder(ctx, o.ID)
		if err != nil {
			return err
		}
		*o = *fresh
	}
	return ErrStale
}

// loadOrder loads an order owned by acct and refreshes its status.
func (s *Server) loadOrder(ctx context.Context, acct *Account, id string) (*Order, *Problem) {
	o, err := s.store.GetOrder(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound("order")
	}
	if err != nil {
		return nil, s.internal("loading order", err)
	}
	if o.AccountID != acct.ID {
		return nil, unauthorized("order belongs to another account")
	}
	if err := s.refreshOrder(ctx, o); err != nil {
		return nil, s.internal("refreshing order", err)
	}
	return o, nil
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if !req.postAsGet() {
		s.problem(w, malformed("order fetch must be POST-as-GET"))
		return
	}
	o, prob := s.loadOrder(r.Context(), req.account, id)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if o.Status == StatusProcessing {
		retryAfter(w, 2*time.Second)
	}
	s.writeJSON(w, http.StatusOK, s.orderJSON(o))
}

func (s *Server) loadAuthz(ctx context.Context, acct *Account, id string) (*Authorization, *Problem) {
	az, err := s.store.GetAuthorization(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound("authorization")
	}
	if err != nil {
		return nil, s.internal("loading authorization", err)
	}
	if az.AccountID != acct.ID {
		return nil, unauthorized("authorization belongs to another account")
	}
	if err := s.refreshAuthz(ctx, az); err != nil {
		return nil, s.internal("refreshing authorization", err)
	}
	return az, nil
}

// handleAuthz implements authorization fetch and deactivation (§7.5, §7.5.2).
func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	ctx := r.Context()
	az, prob := s.loadAuthz(ctx, req.account, id)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if req.postAsGet() {
		s.writeJSON(w, http.StatusOK, s.authzJSON(az))
		return
	}
	var p struct {
		Status string `json:"status"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	if p.Status != StatusDeactivated {
		s.problem(w, malformed("authorization status may only be set to deactivated"))
		return
	}
	for range 5 {
		if az.Status != StatusPending && az.Status != StatusValid {
			s.problem(w, malformed("authorization is %s and cannot be deactivated", az.Status))
			return
		}
		az.Status = StatusDeactivated
		err := s.store.UpdateAuthorization(ctx, az)
		if err == nil {
			s.writeJSON(w, http.StatusOK, s.authzJSON(az))
			return
		}
		if !errors.Is(err, ErrStale) {
			s.problem(w, s.internal("updating authorization", err))
			return
		}
		if az, prob = s.loadAuthz(ctx, req.account, id); prob != nil {
			s.problem(w, prob)
			return
		}
	}
	s.problem(w, serverInternal("too much contention updating authorization"))
}

// handleChallenge implements challenge fetch and response (§7.5.1).
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, rel, authzID, challID string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	ctx := r.Context()
	acct := req.account
	if !req.postAsGet() {
		var p map[string]any
		if prob := decodePayload(req.payload, &p); prob != nil {
			s.problem(w, prob)
			return
		}
	}
	for range 5 {
		az, prob := s.loadAuthz(ctx, acct, authzID)
		if prob != nil {
			s.problem(w, prob)
			return
		}
		idx := -1
		for i := range az.Challenges {
			if az.Challenges[i].ID == challID {
				idx = i
			}
		}
		if idx < 0 {
			s.problem(w, notFound("challenge"))
			return
		}
		ch := &az.Challenges[idx]
		up := linkHeader(s.url(pathAuthz+az.ID), "up")
		if req.postAsGet() || ch.Status != StatusPending || az.Status != StatusPending {
			if ch.Status == StatusProcessing {
				retryAfter(w, 2*time.Second)
			}
			w.Header().Add("Link", up)
			s.writeJSON(w, http.StatusOK, s.challengeJSON(az, ch))
			return
		}
		validator, ok := s.validators[ch.Type]
		if !ok {
			s.problem(w, serverInternal("no validator for %s", ch.Type))
			return
		}
		ch.Status = StatusProcessing
		err := s.store.UpdateAuthorization(ctx, az)
		if errors.Is(err, ErrStale) {
			continue
		}
		if err != nil {
			s.problem(w, s.internal("updating challenge", err))
			return
		}
		if !s.startValidation(validator, az.ID, ch.ID, az.Identifier, ch.Token, keyAuthorization(ch.Token, req.thumb)) {
			s.problem(w, serverInternal("server is shutting down"))
			return
		}
		retryAfter(w, 2*time.Second)
		w.Header().Add("Link", up)
		s.writeJSON(w, http.StatusOK, s.challengeJSON(az, ch))
		return
	}
	s.problem(w, serverInternal("too much contention updating challenge"))
}

func (s *Server) startValidation(v Validator, authzID, challID string, id Identifier, token, keyAuth string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	go s.runValidation(v, authzID, challID, id, token, keyAuth)
	return true
}

func (s *Server) runValidation(v Validator, authzID, challID string, id Identifier, token, keyAuth string) {
	defer s.wg.Done()
	var verr error
	select {
	case s.sem <- struct{}{}:
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ValidationTimeout)
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("acme: validator panicked", "panic", r)
					verr = serverInternal("validation failed")
				}
			}()
			verr = v.Validate(ctx, id, token, keyAuth)
		}()
		cancel()
		<-s.sem
	case <-s.ctx.Done():
		verr = serverInternal("server shut down before validation")
	}
	var chErr *Problem
	if verr != nil {
		chErr = asProblem(verr, ProbUnauthorized, http.StatusForbidden, "challenge validation failed")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), 10*time.Second)
	defer cancel()
	for range 10 {
		az, err := s.store.GetAuthorization(ctx, authzID)
		if err != nil {
			s.log.Error("acme: recording validation result", "authz", authzID, "err", err)
			return
		}
		var ch *Challenge
		for i := range az.Challenges {
			if az.Challenges[i].ID == challID {
				ch = &az.Challenges[i]
			}
		}
		if ch == nil || ch.Status != StatusProcessing {
			return
		}
		now := s.now().UTC()
		if chErr == nil {
			ch.Status, ch.Validated = StatusValid, now
			if az.Status == StatusPending && now.Before(az.Expires) {
				az.Status = StatusValid
				az.Expires = now.Add(s.cfg.AuthzLifetime).Truncate(time.Second)
			}
		} else {
			ch.Status, ch.Error = StatusInvalid, chErr
			if az.Status == StatusPending {
				az.Status = StatusInvalid
			}
		}
		err = s.store.UpdateAuthorization(ctx, az)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrStale) {
			s.log.Error("acme: recording validation result", "authz", authzID, "err", err)
			return
		}
	}
	s.log.Error("acme: recording validation result: too much contention", "authz", authzID)
}
