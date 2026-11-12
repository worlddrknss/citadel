package acme

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

const maxContacts = 10

type accountJSON struct {
	Status               string   `json:"status"`
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	Orders               string   `json:"orders"`
}

func (s *Server) accountJSON(a *Account) accountJSON {
	return accountJSON{
		Status:               a.Status,
		Contact:              a.Contact,
		TermsOfServiceAgreed: a.TermsOfServiceAgreed,
		Orders:               s.url(pathAcct + a.ID + "/orders"),
	}
}

func validateContacts(contacts []string) *Problem {
	if len(contacts) > maxContacts {
		return newProblem(ProbInvalidContact, http.StatusBadRequest, "at most %d contacts are allowed", maxContacts)
	}
	for _, c := range contacts {
		addr, ok := strings.CutPrefix(c, "mailto:")
		if !ok {
			return newProblem(ProbUnsupportedContact, http.StatusBadRequest, "only mailto: contacts are supported")
		}
		if addr == "" || strings.ContainsAny(addr, ",?;<> \t\r\n") || len(c) > 254 {
			return newProblem(ProbInvalidContact, http.StatusBadRequest, "invalid contact %q", c)
		}
		if a, err := mail.ParseAddress(addr); err != nil || a.Address != addr || a.Name != "" {
			return newProblem(ProbInvalidContact, http.StatusBadRequest, "invalid contact %q", c)
		}
	}
	return nil
}

// handleNewAccount implements RFC 8555 §7.3.
func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request, rel string) {
	req, prob := s.verify(r, rel, jwkOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	var p struct {
		Contact                []string        `json:"contact"`
		TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	ctx := r.Context()
	existing, err := s.store.GetAccountByThumbprint(ctx, req.thumb)
	switch {
	case err == nil:
		w.Header().Set("Location", s.url(pathAcct+existing.ID))
		if existing.Status != StatusValid {
			s.problem(w, unauthorized("account is %s", existing.Status))
			return
		}
		s.writeJSON(w, http.StatusOK, s.accountJSON(existing))
		return
	case !errors.Is(err, ErrNotFound):
		s.problem(w, s.internal("loading account", err))
		return
	}
	if p.OnlyReturnExisting {
		s.problem(w, newProblem(ProbAccountDoesNotExist, http.StatusBadRequest, "no account exists for this key"))
		return
	}
	if s.cfg.TermsOfService != "" && !p.TermsOfServiceAgreed {
		s.problem(w, malformed("terms of service must be agreed to"))
		return
	}
	if prob := validateContacts(p.Contact); prob != nil {
		s.problem(w, prob)
		return
	}
	acct := &Account{
		ID:                   randomID(12),
		Status:               StatusValid,
		Contact:              p.Contact,
		TermsOfServiceAgreed: p.TermsOfServiceAgreed,
		KeyThumbprint:        req.thumb,
		CreatedAt:            s.now().UTC(),
	}
	hasEAB := len(p.ExternalAccountBinding) > 0 && string(p.ExternalAccountBinding) != "null"
	if s.cfg.RequireEAB && !hasEAB {
		s.problem(w, newProblem(ProbExternalAccountRequired, http.StatusForbidden, "an external account binding is required"))
		return
	}
	if hasEAB && s.cfg.EABKeys != nil {
		kid, ref, prob := verifyEAB(p.ExternalAccountBinding, req.url, req.key, func(kid string) ([]byte, string, error) {
			return s.cfg.EABKeys.Lookup(ctx, kid)
		})
		if prob != nil {
			s.problem(w, prob)
			return
		}
		acct.EABKeyID, acct.AccountRef = kid, ref
	}
	if acct.KeyJWK, err = canonicalJWK(req.key); err != nil {
		s.problem(w, s.internal("encoding key", err))
		return
	}
	if err := s.store.CreateAccount(ctx, acct); err != nil {
		if errors.Is(err, ErrDuplicate) {
			// Lost a race with a concurrent newAccount for the same key.
			if ex, err2 := s.store.GetAccountByThumbprint(ctx, req.thumb); err2 == nil {
				w.Header().Set("Location", s.url(pathAcct+ex.ID))
				s.writeJSON(w, http.StatusOK, s.accountJSON(ex))
				return
			}
		}
		s.problem(w, s.internal("creating account", err))
		return
	}
	w.Header().Set("Location", s.url(pathAcct+acct.ID))
	s.writeJSON(w, http.StatusCreated, s.accountJSON(acct))
}

// handleAccount implements account fetch, update and deactivation (§7.3.2,
// §7.3.6).
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if req.account.ID != id {
		s.problem(w, unauthorized("request is not signed by this account"))
		return
	}
	acct := req.account
	if req.postAsGet() {
		s.writeJSON(w, http.StatusOK, s.accountJSON(acct))
		return
	}
	var p struct {
		Contact              *[]string `json:"contact"`
		Status               string    `json:"status"`
		TermsOfServiceAgreed *bool     `json:"termsOfServiceAgreed"`
	}
	if prob := decodePayload(req.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	if p.Status != "" && p.Status != StatusDeactivated {
		s.problem(w, malformed("account status may only be set to deactivated"))
		return
	}
	if p.Contact != nil {
		if prob := validateContacts(*p.Contact); prob != nil {
			s.problem(w, prob)
			return
		}
	}
	err := s.updateAccount(r.Context(), acct, func(a *Account) *Problem {
		if a.Status != StatusValid {
			return unauthorized("account is %s", a.Status)
		}
		if p.Contact != nil {
			a.Contact = *p.Contact
		}
		if p.TermsOfServiceAgreed != nil && *p.TermsOfServiceAgreed {
			a.TermsOfServiceAgreed = true
		}
		if p.Status == StatusDeactivated {
			a.Status = StatusDeactivated
		}
		return nil
	})
	if err != nil {
		s.problem(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.accountJSON(acct))
}

// updateAccount applies fn with optimistic-concurrency retries. On success
// *acct holds the stored result.
func (s *Server) updateAccount(ctx context.Context, acct *Account, fn func(*Account) *Problem) *Problem {
	for range 5 {
		if prob := fn(acct); prob != nil {
			return prob
		}
		err := s.store.UpdateAccount(ctx, acct)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrDuplicate) {
			return newProblem(ProbMalformed, http.StatusConflict, "key is already in use by another account")
		}
		if !errors.Is(err, ErrStale) {
			return s.internal("updating account", err)
		}
		fresh, err := s.store.GetAccount(ctx, acct.ID)
		if err != nil {
			return s.internal("reloading account", err)
		}
		*acct = *fresh
	}
	return serverInternal("too much contention updating account")
}

func (s *Server) handleOrderList(w http.ResponseWriter, r *http.Request, rel, id string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if req.account.ID != id {
		s.problem(w, unauthorized("request is not signed by this account"))
		return
	}
	ids, err := s.store.ListOrderIDs(r.Context(), id)
	if err != nil {
		s.problem(w, s.internal("listing orders", err))
		return
	}
	urls := make([]string, 0, len(ids))
	for _, oid := range ids {
		urls = append(urls, s.url(pathOrder+oid))
	}
	s.writeJSON(w, http.StatusOK, map[string][]string{"orders": urls})
}

// handleKeyChange implements account key rollover (§7.3.5).
func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request, rel string) {
	req, prob := s.verify(r, rel, kidOnly)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	inner, prob := parseJWS(req.payload)
	if prob != nil {
		prob.Detail = "inner JWS: " + prob.Detail
		s.problem(w, prob)
		return
	}
	h := inner.header
	if prob := checkOuterAlg(h.Alg); prob != nil {
		s.problem(w, prob)
		return
	}
	if len(h.JWK) == 0 || h.KID != "" {
		s.problem(w, malformed("inner JWS must contain a jwk and no kid"))
		return
	}
	if h.Nonce != "" {
		s.problem(w, malformed("inner JWS must not contain a nonce"))
		return
	}
	if h.URL != req.url {
		s.problem(w, malformed("inner JWS url does not match the outer url"))
		return
	}
	newKey, prob := parseJWK(h.JWK)
	if prob != nil {
		s.problem(w, prob)
		return
	}
	if !algMatchesKey(h.Alg, newKey) {
		s.problem(w, badSigAlg("inner JWS algorithm does not match its key"))
		return
	}
	if err := verifySignature(h.Alg, newKey, inner.signingInput, inner.signature); err != nil {
		s.problem(w, malformed("inner JWS signature verification failed"))
		return
	}
	var p struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if prob := decodePayload(inner.payload, &p); prob != nil {
		s.problem(w, prob)
		return
	}
	acct := req.account
	if p.Account != s.url(pathAcct+acct.ID) {
		s.problem(w, malformed("inner payload account does not match the signing account"))
		return
	}
	oldKey, prob := parseJWK(p.OldKey)
	if prob != nil || !publicKeysEqual(oldKey, req.key) {
		s.problem(w, malformed("inner payload oldKey does not match the current account key"))
		return
	}
	newThumb, err := Thumbprint(newKey)
	if err != nil {
		s.problem(w, s.internal("computing thumbprint", err))
		return
	}
	if ex, err := s.store.GetAccountByThumbprint(r.Context(), newThumb); err == nil {
		w.Header().Set("Location", s.url(pathAcct+ex.ID))
		s.problem(w, newProblem(ProbMalformed, http.StatusConflict, "new key is already in use by another account"))
		return
	}
	newJWK, err := canonicalJWK(newKey)
	if err != nil {
		s.problem(w, s.internal("encoding key", err))
		return
	}
	oldThumb := req.thumb
	prob = s.updateAccount(r.Context(), acct, func(a *Account) *Problem {
		if a.KeyThumbprint != oldThumb {
			return malformed("account key changed concurrently")
		}
		a.KeyJWK, a.KeyThumbprint = newJWK, newThumb
		return nil
	})
	if prob != nil {
		s.problem(w, prob)
		return
	}
	s.writeJSON(w, http.StatusOK, s.accountJSON(acct))
}
