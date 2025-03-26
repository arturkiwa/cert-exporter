package exporters

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/arturkiwa/cert-exporter/src/metrics"
	"github.com/pavel-v-chernykh/keystore-go"
)

// JKSExporter exports certs from JKS keystores in Kubernetes Secrets
// It mimics the behavior of SecretExporter

type JKSExporter struct{}

func (e *JKSExporter) ExportMetrics(jksData []byte, password string, keyName, secretName, secretNamespace string) error {
	ks, err := keystore.Decode(bytes.NewReader(jksData), []byte(password))
	if err != nil {
		return fmt.Errorf("failed to decode JKS: %v", err)
	}

	for alias, entry := range ks {
		pkEntry, ok := entry.(*keystore.PrivateKeyEntry)
		if !ok {
			continue
		}

		for i, cert := range pkEntry.CertificateChain {
			parsedCert, err := x509.ParseCertificate(cert.Content)
			if err != nil {
				return fmt.Errorf("failed to parse cert at alias %s[%d]: %v", alias, i, err)
			}

			metricsData := secondsToExpiryFromCert(parsedCert)

			metrics.SecretExpirySeconds.WithLabelValues(keyName, metricsData.issuer, metricsData.cn, secretName, secretNamespace).Set(metricsData.durationUntilExpiry)
			metrics.SecretNotAfterTimestamp.WithLabelValues(keyName, metricsData.issuer, metricsData.cn, secretName, secretNamespace).Set(metricsData.notAfter)
			metrics.SecretNotBeforeTimestamp.WithLabelValues(keyName, metricsData.issuer, metricsData.cn, secretName, secretNamespace).Set(metricsData.notBefore)
		}
	}

	return nil
}

func (e *JKSExporter) ResetMetrics() {
	metrics.SecretExpirySeconds.Reset()
	metrics.SecretNotAfterTimestamp.Reset()
	metrics.SecretNotBeforeTimestamp.Reset()
}

