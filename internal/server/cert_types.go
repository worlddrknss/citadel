package server

type certificateAuthorityConfig struct {
	KeyAlgorithm     string        `json:"KeyAlgorithm"`
	SigningAlgorithm string        `json:"SigningAlgorithm"`
	Subject          subjectConfig `json:"Subject"`
}

type subjectConfig struct {
	Country          string `json:"Country,omitempty"`
	State            string `json:"State,omitempty"`
	Locality         string `json:"Locality,omitempty"`
	Organization     string `json:"Organization,omitempty"`
	OrganizationUnit string `json:"OrganizationalUnit,omitempty"`
	CommonName       string `json:"CommonName,omitempty"`
}

type createCertificateAuthorityRequest struct {
	CertificateAuthorityConfiguration certificateAuthorityConfig `json:"CertificateAuthorityConfiguration"`
	CAType                            string                     `json:"Type"`
}

type createCertificateAuthorityResponse struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
}

type describeCertificateAuthorityRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
}

type certificateAuthorityRecord struct {
	ARN         string `json:"Arn"`
	Type        string `json:"Type"`
	Status      string `json:"Status"`
	Certificate string `json:"Certificate,omitempty"`
	CreatedAt   string `json:"CreatedAt,omitempty"`
}

type describeCertificateAuthorityResponse struct {
	CertificateAuthority certificateAuthorityRecord `json:"CertificateAuthority"`
}

type issueCertificateRequest struct {
	CertificateAuthorityARN string       `json:"CertificateAuthorityArn"`
	CSR                     string       `json:"Csr"`
	SigningAlgorithm        string       `json:"SigningAlgorithm"`
	Validity                validitySpec `json:"Validity"`
}

type validitySpec struct {
	Value int64  `json:"Value"`
	Type  string `json:"Type"`
}

type issueCertificateResponse struct {
	CertificateARN string `json:"CertificateArn"`
}

type getCertificateRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
	CertificateARN          string `json:"CertificateArn"`
}

type getCertificateResponse struct {
	Certificate string `json:"Certificate"`
}

type revokeCertificateRequest struct {
	CertificateAuthorityARN string `json:"CertificateAuthorityArn"`
	CertificateARN          string `json:"CertificateArn"`
	RevocationReason        string `json:"RevocationReason"`
}

// ACM (Certificate Manager) types - facade over acm-pca
type requestCertificateRequest struct {
	DomainName       string   `json:"DomainName"`
	ValidationMethod string   `json:"ValidationMethod"`
	SubjectAltNames  []string `json:"SubjectAlternativeNames,omitempty"`
	Idempotency      string   `json:"IdempotencyToken,omitempty"`
}

type requestCertificateResponse struct {
	CertificateARN string `json:"CertificateArn"`
}

type describeCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type describeCertificateResponse struct {
	Certificate certificateDetail `json:"Certificate"`
}

type certificateDetail struct {
	ARN                     string   `json:"CertificateArn"`
	DomainName              string   `json:"DomainName"`
	SubjectAlternativeNames []string `json:"SubjectAlternativeNames,omitempty"`
	Status                  string   `json:"Status"`
	Serial                  string   `json:"Serial,omitempty"`
	NotBefore               string   `json:"NotBefore,omitempty"`
	NotAfter                string   `json:"NotAfter,omitempty"`
	CreatedAt               string   `json:"CreatedAt,omitempty"`
}

type listCertificatesRequest struct {
	Limit  int    `json:"MaxItems,omitempty"`
	Marker string `json:"Marker,omitempty"`
}

type listCertificatesResponse struct {
	CertificateSummaryList []certificateSummary `json:"CertificateSummaryList"`
	NextMarker             string               `json:"NextMarker,omitempty"`
}

type certificateSummary struct {
	ARN        string `json:"CertificateArn"`
	DomainName string `json:"DomainName"`
	Status     string `json:"Status"`
	CreatedAt  string `json:"CreatedAt,omitempty"`
}

type deleteCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type acmGetCertificateRequest struct {
	CertificateARN string `json:"CertificateArn"`
}

type acmGetCertificateResponse struct {
	Certificate string `json:"Certificate"`
	CertChain   string `json:"CertificateChain,omitempty"`
	PrivateKey  string `json:"PrivateKey,omitempty"`
}
