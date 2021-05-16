package ejbcarest

// TokenType is the type of the token associated with an end entity.
type TokenType string

// UserStatus is the status of a user.
type UserStatus string

// RevokeReason is the revocation reason.
type RevokeReason int

const (
	UserGenerated = TokenType("USERGENERATED")
	PKCS12        = TokenType("P12")
	JKS           = TokenType("JKS")
	PEM           = TokenType("PEM")

	New         = UserStatus("NEW")
	Failed      = UserStatus("FAILED")
	Initialised = UserStatus("INITIALIZED")
	InProcess   = UserStatus("INPROCESS")
	Generated   = UserStatus("GENERATED")
	Revoked     = UserStatus("REVOKED")
	Historical  = UserStatus("HISTORICAL")

	Unspecified          = RevokeReason(0)
	KeyCompromise        = RevokeReason(1)
	CACompromise         = RevokeReason(2)
	AffiliationChanged   = RevokeReason(3)
	Superseded           = RevokeReason(4)
	CessationOfOperation = RevokeReason(5)
	CertificateHold      = RevokeReason(6)
	RemoveFromCRL        = RevokeReason(8)
	PrivilegesWithdrawn  = RevokeReason(9)
	AACompromise         = RevokeReason(10)
)

// ExtensionData represents extension data to be associated with end entity.
type ExtensionData struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AddEndEntityRequest represents data to send when adding a new end entity.
type AddEndEntityRequest struct {
	Username               string          `json:"username"`
	Password               string          `json:"password"`
	SubjectDN              string          `json:"subject_dn"`
	SubjectAltName         string          `json:"subject_alt_name"`
	Email                  string          `json:"email"`
	Extensions             []ExtensionData `json:"extension_data"`
	CAName                 string          `json:"ca_name"`
	CertificateProfileName string          `json:"certificate_profile_name"`
	EndEntityProfileName   string          `json:"end_entity_profile_name"`
	Token                  TokenType       `json:"token"`
}

// SetEndEntityStatusRequest represents data to send when setting an end entity status.
type SetEndEntityStatusRequest struct {
	Password string     `json:"password"`
	Token    TokenType  `json:"token"`
	Status   UserStatus `json:"status"`
}

// RevokeEndEntityRequest represents data to send when revoking an end entity.
type RevokeEndEntityRequest struct {
	ReasonCode RevokeReason `json:"reason_code"`
	Delete     bool         `json:"delete"`
}

// SearchEndEntityCriteria represents the search criteria when searching end entity data.
type SearchEndEntityCriteria struct {
	Property  string `json:"property"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
}

// SearchEndEntityRequest represents the data to send when searching for end entities.
type SearchEndEntityRequest struct {
	MaxNumberOfResults int                       `json:"max_number_of_results"`
	Criteria           []SearchEndEntityCriteria `json:"criteria"`
}

// EndEntity represents end entity data.
type EndEntity struct {
	Username       string          `json:"username"`
	DN             string          `json:"dn"`
	SubjectAltName string          `json:"subject_alt_name"`
	Email          string          `json:"email"`
	Status         UserStatus      `json:"status"`
	Token          TokenType       `json:"token"`
	Extensions     []ExtensionData `json:"extension_data"`
}

// SearchEndEntityResponse represents response received from searching end entity data.
type SearchEndEntityResponse struct {
	EndEntities []EndEntity `json:"end_entities"`
	MoreResults bool        `json:"more_results"`
}
