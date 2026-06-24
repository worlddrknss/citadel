package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Approval workflow scaffolding (PLAN.md §6 P8).
//
// A change request captures a proposed write to a single item that must be
// approved before it is applied. This is a minimal, in-memory, per-account
// scaffold: it provides the create → review → approve/reject lifecycle and the
// service + API surface the Svelte UI can build on, without yet persisting to
// Postgres. Approving a request applies the value through the normal service
// path (so versioning, encryption, and audit all happen unchanged).

type changeRequestStatus string

const (
	changeRequestPending  changeRequestStatus = "pending"
	changeRequestApproved changeRequestStatus = "approved"
	changeRequestRejected changeRequestStatus = "rejected"
)

type changeRequest struct {
	ID        string
	Account   string
	Coord     itemCoord
	NewValue  string
	KMSKeyID  string
	Requester string
	Status    changeRequestStatus
	CreatedAt time.Time
	DecidedBy string
	DecidedAt time.Time
}

var (
	errChangeRequestNotFound = errors.New("change request not found")
	errChangeRequestDecided  = errors.New("change request already decided")
)

// approvalRegistry is the in-memory store of change requests, keyed by ID.
type approvalRegistry struct {
	mu  sync.Mutex
	seq int64
	all map[string]*changeRequest
}

func newApprovalRegistry() *approvalRegistry {
	return &approvalRegistry{all: map[string]*changeRequest{}}
}

func accountForApproval(ctx context.Context) string {
	if a, ok := callerAccountFromContext(ctx); ok {
		return a
	}
	return ""
}

// CreateChangeRequest records a proposed write awaiting approval.
func (svc *secretsService) CreateChangeRequest(ctx context.Context, coord itemCoord, newValue, kmsKeyID, requester string) (*changeRequest, error) {
	if err := coord.validate(); err != nil {
		return nil, err
	}
	reg := svc.approvals
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.seq++
	cr := &changeRequest{
		ID:        "cr-" + time.Now().UTC().Format("20060102") + "-" + itoa(reg.seq),
		Account:   accountForApproval(ctx),
		Coord:     coord,
		NewValue:  newValue,
		KMSKeyID:  kmsKeyID,
		Requester: requester,
		Status:    changeRequestPending,
		CreatedAt: time.Now().UTC(),
	}
	reg.all[cr.ID] = cr
	return cr, nil
}

// ListChangeRequests returns the caller account's change requests, newest first.
func (svc *secretsService) ListChangeRequests(ctx context.Context) []changeRequest {
	account := accountForApproval(ctx)
	reg := svc.approvals
	reg.mu.Lock()
	defer reg.mu.Unlock()
	out := make([]changeRequest, 0, len(reg.all))
	for _, cr := range reg.all {
		if cr.Account == account {
			out = append(out, *cr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ApproveChangeRequest applies a pending request and marks it approved.
func (svc *secretsService) ApproveChangeRequest(ctx context.Context, id, approver string) error {
	reg := svc.approvals
	reg.mu.Lock()
	cr, ok := reg.all[id]
	if !ok || cr.Account != accountForApproval(ctx) {
		reg.mu.Unlock()
		return errChangeRequestNotFound
	}
	if cr.Status != changeRequestPending {
		reg.mu.Unlock()
		return errChangeRequestDecided
	}
	coord, value, kmsKeyID := cr.Coord, cr.NewValue, cr.KMSKeyID
	reg.mu.Unlock()

	if _, err := svc.PutItem(ctx, coord, value, kmsKeyID); err != nil {
		return err
	}

	reg.mu.Lock()
	cr.Status = changeRequestApproved
	cr.DecidedBy = approver
	cr.DecidedAt = time.Now().UTC()
	reg.mu.Unlock()
	return nil
}

// RejectChangeRequest marks a pending request rejected without applying it.
func (svc *secretsService) RejectChangeRequest(ctx context.Context, id, approver string) error {
	reg := svc.approvals
	reg.mu.Lock()
	defer reg.mu.Unlock()
	cr, ok := reg.all[id]
	if !ok || cr.Account != accountForApproval(ctx) {
		return errChangeRequestNotFound
	}
	if cr.Status != changeRequestPending {
		return errChangeRequestDecided
	}
	cr.Status = changeRequestRejected
	cr.DecidedBy = approver
	cr.DecidedAt = time.Now().UTC()
	return nil
}

// itoa renders a small positive int64 without importing strconv at call sites.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
