package exporters

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"github.com/arturkiwa/cert-exporter/src/metrics"
	"github.com/pavel-v-chernykh/keystore-go"
	corev1 "k8s.io/api/core/v1"
)

// ParseJKSSecret parses a Kubernetes Secret containing a JKS keystore
// and a second Secret containing the password, returning CertInfo objects
func ParseJKSSecret(jksSecret *corev1.Secret, passwordSecret *corev1.Secret) ([]*metrics.CertInfo, error) {
	jksData, ok := jksSecret.Data["keystore.jks"]
	if !ok {
		return nil, fmt.Errorf("no 'keystore.jks' key in JKS secret")
	}

	passwordBytes, ok := passwordSecret.Data["password"]
	if !ok {
		return nil, fmt.Errorf("no 'password' key in password secret")
	}

	password := string(passwordBytes)

	reader := bytes.NewReader(jksData)
	ks := keystore.New()
	entries, err := ks.Load(reader, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to load keystore: %v", err)
	}

	var certInfos []*metrics.CertInfo

	for alias, entry := range entries {
		pkEntry, ok := entry.(*keystore.PrivateKeyEntry)
		if !ok {
			continue // skip trusted certs etc.
		}

		for i, cert := range pkEntry.CertificateChain {
			parsedCert, err := x509.ParseCertificate(cert.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to parse cert at alias '%s', index %d: %v", alias, i, err)
			}

			certInfos = append(certInfos, &metrics.CertInfo{
				CN:        parsedCert.Subject.CommonName,
				StartDate: parsedCert.NotBefore,
				EndDate:   parsedCert.NotAfter,
				Serial:    parsedCert.SerialNumber.String(),
				Issuer:    parsedCert.Issuer.CommonName,
				Sans:      parsedCert.DNSNames,
				Error:     nil,
			})
		}
	}

	return certInfos, nil
}

