package store

import (
	"time"
)

type PCACertificateAuthority struct {
	CAID        string
	ARN         string
	Type        string
	KMSKeyID    string
	SubjectDN   string
	State       string
	CACertB64   string
	PathLength  *int
	NotBefore   time.Time
	NotAfter    time.Time
	Description string
	Account     string
	// ParentCAID is the Citadel CA that signed a subordinate CA ("" for
	// roots and imported CAs).
	ParentCAID string
	// RestorableUntil is set while the CA is DELETED: it can be restored
	// until then, and is purged after.
	RestorableUntil *time.Time
	// AccountID is the owning tenant; set by the store on reads.
	AccountID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PCACertificate struct {
	CertID           string
	CAID             string
	Serial           string
	CSRB64           string
	CertB64          string
	Status           string
	NotBefore        time.Time
	NotAfter         time.Time
	RevokedAt        *time.Time
	RevocationReason string
	Template         string
	// DeletedAt is set when the certificate was removed from the console
	// inventory; the row stays for the CRL.
	DeletedAt *time.Time
	// AccountID is the owning tenant; set by the store on reads.
	AccountID string
	CreatedAt time.Time
	UpdatedAt time.Time
}
