package sslutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// TimeoutSeconds is the timeout for TLS connections.
	TimeoutSeconds = 10
	// kubernetesCAFileLocation is the Kubernetes CA path mounted in pods.
	kubernetesCAFileLocation = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// selfSignedCertLocation is the path for custom certificates.
	selfSignedCertLocation = "/etc/ssl/selfsign/certificate.crt"
)

// KubernetesCAPresent returns true if the Kubernetes CA file exists.
func KubernetesCAPresent() bool {
	// Check for the Kubernetes CA file.
	return filePresent(kubernetesCAFileLocation)
}

// SelfSignedCAPresent returns true if a custom CA certificate exists.
func SelfSignedCAPresent() bool {
	// Check for the custom CA file.
	return filePresent(selfSignedCertLocation)
}

// filePresent returns true if the specified file exists.
func filePresent(filePath string) bool {
	// Stat the file and check for errors.
	if _, err := os.Stat(filePath); err == nil {
		return true
	}

	return false
}

// certPoolFromFile creates a cert pool from a file.
func certPoolFromFile(filePath string) (*x509.CertPool, error) {
	// Read file bytes from disk.
	certBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Create a cert pool and append certs from file.
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return nil, fmt.Errorf("error parsing certs from file %s", filePath)
	}

	// Log that the certs were appended.
	log.Infoln("Certificate file successfully appended to cert pool")

	return certPool, nil
}

// fetchKubernetesSelfSignedCertFromDisk reads the Kubernetes CA file.
func fetchKubernetesSelfSignedCertFromDisk() ([]byte, error) {
	// Read the Kubernetes CA file.
	certs, err := os.ReadFile(kubernetesCAFileLocation)
	if err != nil {
		return nil, fmt.Errorf("error reading kubernetes certificate authority file: %w", err)
	}

	return certs, nil
}

// fetchSelfSignedCertFromDisk reads the custom certificate file.
func fetchSelfSignedCertFromDisk() ([]byte, error) {
	// Read the custom certificate file.
	certs, err := os.ReadFile(selfSignedCertLocation)
	if err != nil {
		return nil, fmt.Errorf("error reading custom certificate file: %w", err)
	}

	return certs, nil
}

// AppendKubernetesCertsToPool appends the Kubernetes CA to a cert pool.
func AppendKubernetesCertsToPool(pool *x509.CertPool) error {
	// Fetch the Kubernetes cert data.
	certData, err := fetchKubernetesSelfSignedCertFromDisk()
	if err != nil {
		return fmt.Errorf("error fetching cert data from disk: %w", err)
	}

	// Append the certs to the pool.
	ok := pool.AppendCertsFromPEM(certData)
	if !ok {
		log.Warningln("failed to append cert to pem when appending kubernetes certs to cert pool")
	}

	return nil
}

// CreatePool creates a cert pool based on available certs.
func CreatePool() (*x509.CertPool, error) {
	// Use a custom CA when present.
	if SelfSignedCAPresent() {
		log.Infoln("Using self signed CA mounted from", selfSignedCertLocation)
		return certPoolFromFile(selfSignedCertLocation)
	}

	// Use system certs plus Kubernetes CA.
	log.Infoln("Using default certs plus Kubernetes cluster CA mounted from", kubernetesCAFileLocation)
	defaultPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	// Append Kubernetes certs to the pool.
	log.Infoln("Appending Kubernetes SSL certificate authority to cert pool...")
	err = AppendKubernetesCertsToPool(defaultPool)
	if err != nil {
		return nil, err
	}

	return defaultPool, nil
}

// SSLHandshakeWithCertPool performs a TLS handshake with the specified cert pool.
func SSLHandshakeWithCertPool(siteURL *url.URL, certPool *x509.CertPool) error {
	// Ensure an https URL was passed.
	if siteURL.Scheme != "https" {
		return fmt.Errorf("error doing SSL handshake. The url specified %s was not an https URL", siteURL.String())
	}

	// Create a dialer with a timeout.
	dialer := &net.Dialer{
		Timeout: time.Duration(TimeoutSeconds) * time.Second,
	}

	// Dial to the TCP endpoint.
	conn, err := tls.DialWithDialer(dialer, "tcp", siteURL.Hostname()+":"+siteURL.Port(), &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
	})
	if err != nil {
		return fmt.Errorf("error making connection to perform TLS handshake: %w", err)
	}
	defer conn.Close()

	// Perform the SSL handshake.
	err = conn.Handshake()
	if err != nil {
		return fmt.Errorf("unable to perform TLS handshake: %w", err)
	}

	return nil
}

// SSLHandshake performs a TLS handshake using the system cert pool.
func SSLHandshake(siteURL *url.URL) error {
	// Load the system cert pool.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	return SSLHandshakeWithCertPool(siteURL, certPool)
}

// FetchSelfSignedCertFromDisk fetches the self-signed cert placed on disk within pods.
func FetchSelfSignedCertFromDisk() ([]byte, error) {
	// Delegate to the private fetch function for external use.
	return fetchSelfSignedCertFromDisk()
}
