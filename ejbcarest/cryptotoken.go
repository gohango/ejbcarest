package ejbcarest

// ActivateCryptoTokenRequest represents the data to send when calling activating a crypto token.
type ActivateCryptoTokenRequest struct {
	ActivationCode string `json:"activation_code"`
}

// GenerateKeysRequest represents the data to be send when generating new key-pair.
type GenerateKeysRequest struct {
	Alias     string `json:"key_pair_alias"`
	Algorithm string `json:"key_alg"`
	Spec      string `json:"key_spec"`
}
