package server

import (
	"strings"
	"time"

	"github.com/worlddrknss/citadel/internal/store"
)

// Console roles and administration scopes
//
// Every console user has a global role (viewer < editor < admin) and may hold
// a per-account role through a membership (user_accounts). A session is
// always scoped to one account, and its effective role is the membership role
// in that account when the membership carries a valid role, falling back to
// the user's global role (legacy memberships, e.g. "Owner", and accounts
// listed only in the user's static account list).
//
// Administration has two scopes:
//
//   - Account admin: effective role admin in the session's current account.
//     Administers that account only: its memberships (assign/remove/change
//     role), users who belong to no other account, and every account-scoped
//     resource (keys, secrets, certificates...). Cannot create or delete
//     accounts, see other accounts' members, change a user's global role, or
//     change organization settings.
//
//   - Platform admin: global role admin AND flagged platformAdmin
//     (ui_users.platform_admin), or an admin configured through the
//     environment (KMS_UI_USERS_JSON / KMS_UI_PASSWORD), or the admin created
//     by first-run bootstrap (stored with the flag). Administers every
//     account, all users and the organization settings. Platform rights are
//     not carried by access-key (bearer) tokens, which are account-scoped.
//
// The roles are re-resolved from the store on every request, so removing a
// membership, demoting or deleting a user takes effect immediately on their
// existing sessions.

// uiSession is the authenticated console caller for one request.
type uiSession struct {
	// SessionID is the persistent session's public ID; empty for bearer
	// tokens and the insecure-dev local admin.
	SessionID     string
	Username      string
	AccountID     string // current account context for this session
	Role          string // effective role in AccountID
	DisplayName   string
	Accounts      []string // all accounts the user belongs to
	PlatformAdmin bool
	ViaToken      bool // authenticated by an access-key bearer token
	Method        string
	CreatedAt     time.Time
	LastSeenAt    time.Time
}

// dummyPasswordHash is a fixed, valid PBKDF2 hash (current parameters) used to
// spend comparable CPU time when an unknown username is supplied, mitigating
// user-enumeration via response-timing differences. It corresponds to no real
// password.
const dummyPasswordHash = "$pbkdf2-sha256$i=600000$Y0q6S1JhYRMtaRnYXtT+1g$vWWUOxgQ7EVskOU4UldrOnx5wdUEiGPel/mlNcG/O+0"

func uiRoleAtLeast(actual, required string) bool {
	return uiRoleRank(actual) >= uiRoleRank(required)
}

func uiRoleRank(role string) int {
	switch store.NormalizeUIRole(role) {
	case "admin":
		return 3
	case "editor":
		return 2
	default:
		return 1
	}
}

// validRoleName reports whether role is one of the console roles (any case).
// Other values ("Owner", "") mean "use the user's global role".
func validRoleName(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "editor", "viewer":
		return true
	}
	return false
}

// sessionExpired reports whether a session has exceeded its idle or absolute
// lifetime.
func sessionExpired(sess uiSession, now time.Time, idleTTL, absoluteTTL time.Duration) bool {
	if absoluteTTL > 0 && now.Sub(sess.CreatedAt) > absoluteTTL {
		return true
	}
	if idleTTL > 0 && now.Sub(sess.LastSeenAt) > idleTTL {
		return true
	}
	return false
}
