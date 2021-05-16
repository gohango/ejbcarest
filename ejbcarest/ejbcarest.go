// Package ejbcarest provides support to call EJBCA RESTful API.
//
// All the APIs are tested on latest EJBCA version 7.4.3.3. Note that since EJBCA provides
// restful API integration only on its enterprise edition, this library is usable only
// against the EJBCA enterprise edition.
package ejbcarest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type RevokeReasonStr string

const (
	NotRevokedStr           = RevokeReasonStr("NOT_REVOKED")
	UnspecifiedStr          = RevokeReasonStr("UNSPECIFIED")
	KeyCompromiseStr        = RevokeReasonStr("KEY_COMPROMISE")
	CACompromiseStr         = RevokeReasonStr("CA_COMPROMISE")
	AffiliationChangedStr   = RevokeReasonStr("AFFILIATION_CHANGED")
	SupersededStr           = RevokeReasonStr("SUPERSEDED")
	CessationOfOperationStr = RevokeReasonStr("CESSATION_OF_OPERATION")
	CertificateHoldStr      = RevokeReasonStr("CERTIFICATE_HOLD")
	RemoveFromCRLStr        = RevokeReasonStr("REMOVE_FROM_CRL")
	PrivilegesWithdrawnStr  = RevokeReasonStr("PRIVILEGES_WITHDRAWN")
	AACompromiseStr         = RevokeReasonStr("AA_COMPROMISE")
)

// EJBCAError represents EJBCA error response.
type EJBCAError struct {
	Code       int    `json:"error_code"`
	Message    string `json:"error_message"`
	fullString string
}

func (err *EJBCAError) Error() string {
	return err.fullString
}

// Client provides functionalities to call each of EJBCA RESTful operations.
type Client struct {
	ejbcaAddress string
	ejbcaPort    uint
	httpClient   *http.Client
}

// NewClient creates a new EJBCA RESTful client.
func NewClient(httpClient *http.Client, ejbcaAddress string, ejbcaPort uint) *Client {
	return &Client{
		httpClient:   httpClient,
		ejbcaAddress: ejbcaAddress,
		ejbcaPort:    ejbcaPort,
	}
}

// buildEJBCAError build the EJBCA error based on the HTTP response body.
func (client *Client) buildEJBCAError(responseBody []byte) (*EJBCAError, error) {
	ejbcaError := &EJBCAError{}
	err := json.Unmarshal(responseBody, ejbcaError)
	if err != nil {
		return nil, err
	}
	ejbcaError.fullString = string(responseBody)

	return ejbcaError, nil
}

// GetLatestCRL gets the latest CRL issued by a CA.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetLatestCRL(request LatestCRLRequest) (*LatestCRLResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca/%s/getLatestCrl?deltaCrl=%v&crlPartitionIndex=%d",
		client.ejbcaAddress,
		client.ejbcaPort,
		request.IssuerDN,
		request.DeltaCRL,
		request.CRLPartitionIndex)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		// Parse the response JSON.
		crlResp := &LatestCRLResponse{}
		err = json.Unmarshal(body, crlResp)
		if err != nil {
			return nil, err
		}

		return crlResp, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// GetCAs gets the list of CAs with general CA information.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetCAs() (*CAResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca/", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		// Parse the response JSON.
		crlResp := &CAResponse{}
		err = json.Unmarshal(body, crlResp)
		if err != nil {
			return nil, err
		}

		return crlResp, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// DownloadCACertificate downloads a CA certificate based on its subject DN.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) DownloadCACertificate(subjectDN string) (string, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca/%s/certificate/download", client.ejbcaAddress, client.ejbcaPort, subjectDN)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return string(body), nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return "", err
	}

	return "", ejbcaError
}

// GetCAEndpointStatus gets the status of the REST resource.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetCAEndpointStatus() (*StatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca/status", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		statResponse := &StatusResponse{}
		err = json.Unmarshal(body, statResponse)
		if err != nil {
			return nil, err
		}

		return statResponse, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// ActivateCA activates a CA.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) ActivateCA(caName string) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca_management/%s/activate", client.ejbcaAddress, client.ejbcaPort, caName)

	// Call the endpoint.
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// DeactivateCA deactivates a CA.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) DeactivateCA(caName string) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca_management/%s/deactivate", client.ejbcaAddress, client.ejbcaPort, caName)

	// Call the endpoint.
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// GetCAManagementEndpointStatus gets the status of the REST resource.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetCAManagementEndpointStatus() (*StatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/ca_management/status", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		statResponse := &StatusResponse{}
		err = json.Unmarshal(body, statResponse)
		if err != nil {
			return nil, err
		}

		return statResponse, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// ActivateCryptoToken activates a crypto token.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) ActivateCryptoToken(cryptoToken string, request ActivateCryptoTokenRequest) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/cryptotoken/%s/activate", client.ejbcaAddress, client.ejbcaPort, cryptoToken)

	// Build the request
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-type", "application/json")

	// Call the endpoint.
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// DeactivateCryptoToken deactivates a crypto token.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) DeactivateCryptoToken(cryptoToken string) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/cryptotoken/%s/deactivate", client.ejbcaAddress, client.ejbcaPort, cryptoToken)

	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}

	// Call the endpoint.
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// GenerateKeyPair generates a new key-pair inside a crypto token.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GenerateKeyPair(cryptoToken string, request GenerateKeysRequest) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/cryptotoken/%s/generatekeys", client.ejbcaAddress, client.ejbcaPort, cryptoToken)

	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	// Call the endpoint.
	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 201 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// RemoveKeyPair removes a key-pair from a crypto token.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) RemoveKeyPair(cryptoToken, keyAlias string) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/cryptotoken/%s/%s/removekeys", client.ejbcaAddress, client.ejbcaPort, cryptoToken, keyAlias)

	// Call the endpoint.
	resp, err := client.httpClient.Post(url, "application/json", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// GetCryptoTokenEndpointStatus gets the status of the REST resource.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetCryptoTokenEndpointStatus() (*StatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/cryptotoken/status", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		statResponse := &StatusResponse{}
		err = json.Unmarshal(body, statResponse)
		if err != nil {
			return nil, err
		}

		return statResponse, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// AddEndEntity adds a new end entity.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) AddEndEntity(request AddEndEntityRequest) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// SetEndEntityStatus sets status of an end entity.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) SetEndEntityStatus(name string, request SetEndEntityStatusRequest) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity/%s/setstatus", client.ejbcaAddress, client.ejbcaPort, name)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// RevokeEndEntity revokes an end entity.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) RevokeEndEntity(name string, request RevokeEndEntityRequest) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity/%s/revoke", client.ejbcaAddress, client.ejbcaPort, name)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// DeleteEndEntity deletes an end entity.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) DeleteEndEntity(name string) error {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity/%s", client.ejbcaAddress, client.ejbcaPort, name)

	// Call the endpoint.
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		return nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return err
	}

	return ejbcaError
}

// SearchEndEntity searches end entities data.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) SearchEndEntity(request SearchEndEntityRequest) (*SearchEndEntityResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity/search", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		searchResult := &SearchEndEntityResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, err
		}

		return searchResult, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// GetEndEntityEndpointStatus gets the status of the REST resource.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetEndEntityEndpointStatus() (*StatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/endentity/status", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		statResponse := &StatusResponse{}
		err = json.Unmarshal(body, statResponse)
		if err != nil {
			return nil, err
		}

		return statResponse, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// EnrolCertificatePKCS10 enrols a certificate using PEM encoded PKCS#10 CSR.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) EnrolCertificatePKCS10(request PKCS10EnrolRequest) (*PKCS10EnrolResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 201 {
		enrolResp := &PKCS10EnrolResponse{}
		err = json.Unmarshal(body, enrolResp)
		if err != nil {
			return nil, err
		}

		return enrolResp, err
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// EnrolKeystore enrols a keystore.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) EnrolKeystore(request KeystoreEnrolRequest) (*KeystoreEnrolResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/enrollkeystore", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 201 {
		enrolResp := &KeystoreEnrolResponse{}
		err = json.Unmarshal(body, enrolResp)
		if err != nil {
			return nil, err
		}

		return enrolResp, err
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// RevokeCertificate revokes a certificate.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) RevokeCertificate(issuerDN string, serialNumber string, reason RevokeReasonStr, date string) (*RevokeCertificateResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/%s/%s/revoke?reason=%s&date%s", client.ejbcaAddress, client.ejbcaPort, issuerDN, serialNumber, reason, date)

	// Call the endpoint.
	req, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		revokeResp := &RevokeCertificateResponse{}
		err = json.Unmarshal(body, revokeResp)
		if err != nil {
			return nil, err
		}

		return revokeResp, err
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// CheckCertificateRevocationStatus checks the revocation status of a certificate.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) CheckCertificateRevocationStatus(issuerDN string, serialNumber string) (*CertificateRevocationStatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/%s/%s/revocationstatus", client.ejbcaAddress, client.ejbcaPort, issuerDN, serialNumber)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		revokeResp := &CertificateRevocationStatusResponse{}
		err = json.Unmarshal(body, revokeResp)
		if err != nil {
			return nil, err
		}

		return revokeResp, err
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// SearchCertificate searches certificate data.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) SearchCertificate(request SearchCertificateRequest) (*SearchCertificateResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/search", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		searchResult := &SearchCertificateResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, err
		}

		return searchResult, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// FinaliseCertificateEnrolment finalises enrolment after administrator approval using request ID.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) FinaliseCertificateEnrolment(requestID string, request FinaliseCertificateEnrolmentRequest) (*FinaliseCertificateEnrolmentResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/%s/finalize", client.ejbcaAddress, client.ejbcaPort, requestID)

	// Call the endpoint.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 201 {
		searchResult := &FinaliseCertificateEnrolmentResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, err
		}

		return searchResult, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// GetExpiringCertificates gets the list of expiring certificates.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetExpiringCertificates(days uint, offset uint, maxNumberOfResults uint) (*ExpireCertificateResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/expire?days=%d&offset=%d&maxNumberOfResults=%d", client.ejbcaAddress, client.ejbcaPort, days, offset, maxNumberOfResults)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		searchResult := &ExpireCertificateResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, err
		}

		return searchResult, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}

// GetCertificateEndpointStatus gets the status of the REST resource.
// If an error is returned by EJBCA, the error with type EJBCAError will be returned.
func (client *Client) GetCertificateEndpointStatus() (*StatusResponse, error) {
	// Build the URL.
	url := fmt.Sprintf("https://%s:%d/ejbca/ejbca-rest-api/v1/certificate/status", client.ejbcaAddress, client.ejbcaPort)

	// Call the endpoint.
	resp, err := client.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Now check the return code.
	if resp.StatusCode == 200 {
		statResponse := &StatusResponse{}
		err = json.Unmarshal(body, statResponse)
		if err != nil {
			return nil, err
		}

		return statResponse, nil
	}

	ejbcaError, err := client.buildEJBCAError(body)
	if err != nil {
		return nil, err
	}

	return nil, ejbcaError
}
