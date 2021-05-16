# EJBCA REST Client API
This is Go implementation of EJBCA REST API client. The library is developed and tested using latest EJBCA version 7.4.3.3.

## Note
REST API is available only on Enterprise edition of EJBCA. Hence, this library will not work if you are using EJBCA community edition. If you want to learn more about EJBCA Enterprise edition and PKI solutions in general, you may visit [Securemetric](https://www.securemetric.com/pki-solution/).

## Client Authentication
EJBCA requires client to provide client certificate for authentication and authorisation. You need to get your client certificate first prior to establishing connection to EJBCA. If you do not have administrator access or privilege to EJBCA to enrol a new client certificate, you are advised to contact your CA administrator.

## Setting Up Client
Here is an example of setting up the connection and passing in the HTTP client to the library.
```go
// Replace the ManagementCA-chain.pem with your trusted certificate file.
trusted, err := os.ReadFile("ManagementCA-chain.pem") 
if err != nil {
    log.Fatalf("Failed to read trusted CA certificate. %s.", err)
}

certPool := x509.NewCertPool()
certPool.AppendCertsFromPEM(trusted)

// Replace the superadmin.pem and superadmin.key with your client certificate and key files.
clientCert, err := tls.LoadX509KeyPair("superadmin.pem", "superadmin.key")
if err != nil {
    log.Fatalf("Failed to read client certificate. %s.", err)
}

tlsConfig := tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      certPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
}

transport := http.Transport{
    TLSClientConfig: &tlsConfig,
}

httpClient := http.Client{
    Transport: &transport,
}

// Replace the localhost with your EJBCA address and 8443 with your EJBCA port.
client := ejbcarest.NewClient(&httpClient, "localhost", 8443)
```

## Add End Entity
Here is a simple snippet on how to add a new end entity to EJBCA.
```go
err := client.AddEndEntity(ejbcarest.AddEndEntityRequest{
    Username:               "test001",
    Password:               "foo123",
    SubjectDN:              "CN=Test001",
    SubjectAltName:         "",
    Email:                  "test001@testmail.com",
    Extensions:             nil,
    CAName:                 "ManagementCA",
    CertificateProfileName: "ENDUSER",
    EndEntityProfileName:   "EMPTY",
    Token:                  ejbcarest.PKCS12,
})
if err != nil {
    // Do your error handling here
}
// Do your further handling here
```
The above example will create a new end entity with username `test001` and token type `PKCS12`, along with other information.

## Enrol Certificate
Here is a simple snippet on how to enrol a new certificate using PKCS#10 CSR.
```go
enrolResp, err := client.EnrolCertificatePKCS10(ejbcarest.PKCS10EnrolRequest{
    CSR:                    "-----BEGIN CERTIFICATE REQUEST-----\nMIICrjCCAZYCAQAwaTELMAkGA1UEBhMCTVkxDzANBgNVBAMMBkhhbmRyYTEQMA4G\nA1UEBwwHUHVjaG9uZzERMA8GA1UECgwIU3VwZXJoYW4xETAPBgNVBAgMCFNlbGFu\nZ29yMREwDwYDVQQLDAhTdXBlcmhhbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAKB5henacMo5mNUPKD5COERsUMed95yRnjR53wgCp31J70pWOkrD82lK\nIRSYBs2O5zCB1oMaQs5PlZuqFOENkeXuzqQ7P/RKu/mdm1Y5rW5vqCPK6Gpmj67p\nfeWykaHP8thn3Woi6h2fk8q+/mNwu3tdttrmTNpESOtXqTFeFobQ5o9ZdpgcpwHi\nOfiU/bx18mjiDyhAhVMfCppRBLfJOsxxsJ8qAzirbm/UWiuANiOqJq2sXnZzaBEE\n7neLWhQ0/mIiTLlr73m8YHrSnoh5qxQT47Z/6LX8kAd1Wg6FI4evAjeQdf+aKZA9\nkavpYNR9v2+1ZLj/hcdSaot56AsPOdkCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IB\nAQAE0BhT3Xt19wYO2mxgmzcfzMWnYP1xpcpcj4m0YTpJlcqCCzhIeuozxVFKqSzY\nTpUhQcl71SRJvwrgHwKZYa/VjGvr/fF9RGCJxDeXwdmPPCYn9IkUIFlnDtGSMivg\nBq/VGRTo3R7Q8v6n1pwFPzH8kZlYO6bGKuyZige1ex0mHsiF7KleqxGQYpAFnBfO\nydfFmSCSw+mE/bw8WswIcxLiLRkMbXWQXBfrTrMK6AjDg+iHIapBW2yPqqjheMIj\nJWrPYUDxigdYWeVO7L4ld6UWPorgKaHQ/3XmMqEiJ2oC2O2JxqOgDxVXDjHilE1B\n/oGn4i4mEehiuxSrpjVaoF6t\n-----END CERTIFICATE REQUEST-----",
    CertificateProfileName: "ENDUSER",
    EndEntityProfileName:   "EMPTY",
    CAName:                 "ManagementCA",
    Username:               "test001",
    Password:               "foo123",
    IncludeChain:           true,
})
if err != nil {
    // Do your error handling here
}
// Do your further handling here
```

## Further Information
If you need further information on EJBCA REST API, you may visit Primekey's official documentation [here](https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/protocols/ejbca-rest-interface)