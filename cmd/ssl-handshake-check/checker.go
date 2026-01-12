package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/kuberhealthy/ssl-handshake-check/pkg/sslutil"
	log "github.com/sirupsen/logrus"
)

// Checker runs the SSL handshake check logic.
type Checker struct {
	// domainName is the domain to check.
	domainName string
	// portNum is the TLS port to check.
	portNum string
	// selfSigned indicates if the certificate is self-signed.
	selfSigned bool
	// checkTimeout is the timeout for the check.
	checkTimeout time.Duration
}

// NewChecker creates a Checker from configuration.
func NewChecker(cfg *CheckConfig) *Checker {
	// Build the checker instance.
	return &Checker{
		domainName:   cfg.DomainName,
		portNum:      cfg.Port,
		selfSigned:   cfg.SelfSigned,
		checkTimeout: cfg.CheckTimeout,
	}
}

// Run executes the handshake check and reports success or failure.
func (shc *Checker) Run(ctx context.Context, cancel context.CancelFunc) error {
	// Start the async check routine.
	doneChan := make(chan error)
	runTimeout := time.After(shc.checkTimeout)

	go shc.runChecksAsync(doneChan)

	// Wait for timeout or completion.
	select {
	case <-ctx.Done():
		log.Infoln("Cancelling check and shutting down due to interrupt.")
		return reportFailure("Cancelling check and shutting down due to interrupt.")
	case <-runTimeout:
		cancel()
		log.Infoln("Cancelling check and shutting down due to timeout.")
		return reportFailure("Failed to complete SSL handshake in time. Timeout was reached.")
	case err := <-doneChan:
		cancel()
		if err != nil {
			log.Errorln("Error when doing SSL handshake:", err)
			return reportFailure(err.Error())
		}
		return reportSuccess()
	}
}

// runChecksAsync executes the handshake check and sends the result.
func (shc *Checker) runChecksAsync(doneChan chan error) {
	// Perform the check and send the result.
	err := shc.doChecks()
	doneChan <- err
}

// doChecks runs the SSL handshake check.
func (shc *Checker) doChecks() error {
	// Parse the HTTPS URL for the target.
	siteURL, err := url.Parse("https://" + shc.domainName + ":" + shc.portNum)
	if err != nil {
		return err
	}

	// Create a cert pool for this check.
	certPool, err := sslutil.CreatePool()
	if err != nil {
		return fmt.Errorf("error creating cert pool for ssl checks: %w", err)
	}

	// Execute the handshake using the custom pool.
	return sslutil.SSLHandshakeWithCertPool(siteURL, certPool)
}
