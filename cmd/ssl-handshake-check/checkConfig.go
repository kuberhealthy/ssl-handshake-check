package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/kuberhealthy/kuberhealthy/v3/pkg/checkclient"
	log "github.com/sirupsen/logrus"
)

const (
	// defaultCheckTimeout is the fallback timeout for the check.
	defaultCheckTimeout = 20 * time.Second
)

// CheckConfig stores configuration for the SSL handshake check.
type CheckConfig struct {
	// DomainName is the domain to check.
	DomainName string
	// Port is the TLS port to check.
	Port string
	// SelfSigned indicates if the certificate is self-signed.
	SelfSigned bool
	// CheckTimeout is the timeout for the check.
	CheckTimeout time.Duration
}

// parseConfig reads environment variables and builds a CheckConfig.
func parseConfig() (*CheckConfig, error) {
	// Start with the default timeout.
	checkTimeout := defaultCheckTimeout

	// Override using the Kuberhealthy deadline when available.
	deadline, err := checkclient.GetDeadline()
	if err != nil {
		log.Infoln("There was an issue getting the check deadline:", err.Error())
	}
	checkTimeout = deadline.Sub(time.Now().Add(time.Second * 5))
	log.Infoln("Check time limit set to:", checkTimeout)

	// Read required domain name.
	domainName := os.Getenv("DOMAIN_NAME")
	if len(domainName) == 0 {
		return nil, fmt.Errorf("DOMAIN_NAME environment variable has not been set")
	}

	// Read required port.
	portNum := os.Getenv("PORT")
	if len(portNum) == 0 {
		return nil, fmt.Errorf("PORT environment variable has not been set")
	}

	// Read required self-signed flag.
	selfSignedEnv := os.Getenv("SELF_SIGNED")
	if len(selfSignedEnv) == 0 {
		return nil, fmt.Errorf("SELF_SIGNED environment variable has not been set")
	}
	selfSignedBool, err := strconv.ParseBool(selfSignedEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SELF_SIGNED: %w", err)
	}

	// Assemble configuration.
	cfg := &CheckConfig{}
	cfg.DomainName = domainName
	cfg.Port = portNum
	cfg.SelfSigned = selfSignedBool
	cfg.CheckTimeout = checkTimeout

	return cfg, nil
}
