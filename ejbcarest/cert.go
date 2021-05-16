package ejbcarest

import "time"

// PKCS10EnrolRequest represents data to send to enrol certificate using PKCS#10.
type PKCS10EnrolRequest struct {
	CSR                    string `json:"certificate_request"`
	CertificateProfileName string `json:"certificate_profile_name"`
	EndEntityProfileName   string `json:"end_entity_profile_name"`
	CAName                 string `json:"certificate_authority_name"`
	Username               string `json:"username"`
	Password               string `json:"password"`
	IncludeChain           bool   `json:"include_chain"`
}

// PKCS10EnrolResponse represents response received after successful certificate enrolment using PKCS#10.
type PKCS10EnrolResponse struct {
	Certificate      string   `json:"certificate"`
	SerialNumber     string   `json:"serial_number"`
	ResponseFormat   string   `json:"response_format"`
	CertificateChain []string `json:"certificate_chain"`
}

// KeystoreEnrolRequest represents data to send to enrol keystore.
type KeystoreEnrolRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Algorithm string `json:"key_alg"`
	Spec      string `json:"key_spec"`
}

// KeystoreEnrolResponse represents response received after successful keystore enrolment.
type KeystoreEnrolResponse struct {
	Certificate      string   `json:"certificate"`
	SerialNumber     string   `json:"serial_number"`
	ResponseFormat   string   `json:"response_format"`
	CertificateChain []string `json:"certificate_chain"`
}

// RevokeCertificateResponse represents response received after successfully revoke a certificate.
type RevokeCertificateResponse struct {
	IssuerDN         string    `json:"issuer_dn"`
	SerialNumber     string    `json:"serial_number"`
	RevocationReason string    `json:"revocation_reason"`
	RevocationDate   time.Time `json:"revocation_date"`
	Message          string    `json:"message"`
	Revoked          bool      `json:"revoked"`
}

// CertificateRevocationStatusResponse represents response received upon checking the certificate revocation status.
type CertificateRevocationStatusResponse struct {
	IssuerDN         string    `json:"issuer_dn"`
	SerialNumber     string    `json:"serial_number"`
	RevocationReason string    `json:"revocation_reason"`
	RevocationDate   time.Time `json:"revocation_date"`
	Message          string    `json:"message"`
	Revoked          bool      `json:"revoked"`
}

// SearchCertificateCriteria defines the criteria to search certificate data.
type SearchCertificateCriteria struct {
	Property  string `json:"property"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
}

// SearchCertificateRequest represents the data to send when searching for certificate data.
type SearchCertificateRequest struct {
	MaxNumberOfResults int                         `json:"max_number_of_results"`
	Criteria           []SearchCertificateCriteria `json:"criteria"`
}

// Certificate represents the certificate data.
type Certificate struct {
	Certificate      string   `json:"certificate"`
	SerialNumber     string   `json:"serial_number"`
	ResponseFormat   string   `json:"response_format"`
	CertificateChain []string `json:"certificate_chain"`
}

// SearchCertificateResponse represents response received from searching certificate data.
type SearchCertificateResponse struct {
	Certificates []Certificate `json:"certificates"`
	MoreResults  bool          `json:"more_results"`
}

// FinaliseCertificateEnrolmentRequest represents data to send when finalising certificate enrolment request based on request ID.
type FinaliseCertificateEnrolmentRequest struct {
	ResponseFormat string `json:"response_format"`
	Password       string `json:"password"`
}

// FinaliseCertificateEnrolmentResponse represents data returned after finalising the certificate enrolment based on request ID.
type FinaliseCertificateEnrolmentResponse struct {
	Certificate      string   `json:"certificate"`
	SerialNumber     string   `json:"serial_number"`
	ResponseFormat   string   `json:"response_format"`
	CertificateChain []string `json:"certificate_chain"`
}

// PaginationRestResponseComponent represents paging data upon searching expiring certificates..
type PaginationRestResponseComponent struct {
	MoreResults     bool `json:"more_results"`
	NextOffset      uint `json:"next_offset"`
	NumberOfResults uint `json:"number_of_results"`
}

// CertificateRestResponse represents element that stores the list of certificates upon searching expiring certificates.
type CertificateRestResponse struct {
	Certificates []Certificate `json:"certificates"`
}

// ExpireCertificateResponse represents data returned after successfully querying for expiring certificates.
type ExpireCertificateResponse struct {
	Pagination   PaginationRestResponseComponent `json:"pagination_rest_response_component"`
	Certificates CertificateRestResponse         `json:"certificates_rest_response"`
}
