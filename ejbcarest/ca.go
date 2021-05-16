package ejbcarest

import "time"

// LatestCRLRequest represents data to send when calling getLatestCrl endpoint.
type LatestCRLRequest struct {
	IssuerDN          string
	DeltaCRL          bool
	CRLPartitionIndex int
}

// LatestCRLResponse represents response from calling getLatestCrl endpoint.
type LatestCRLResponse struct {
	CRL    string `json:"crl"`
	Format string `json:"response_format"`
}

// CA represents a CA's general information returned by EJBCA.
type CA struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	SubjectDN      string    `json:"subject_dn"`
	IssuerDN       string    `json:"issuer_dn"`
	ExpirationDate time.Time `json:"expiration_date"`
}

// CAResponse represents response from calling ca endpoint.
type CAResponse struct {
	CAs []CA `json:"certificate_authorities"`
}

// StatusResponse represents response from calling status endpoint.
type StatusResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
}
