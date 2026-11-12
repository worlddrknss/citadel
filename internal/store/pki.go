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
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
