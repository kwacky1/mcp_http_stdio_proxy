package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// loadPrivateKey loads and parses the RSA private key for signing JWTs
func (h *Handler) loadPrivateKey() (*rsa.PrivateKey, error) {
	h.privateKeyMu.RLock()
	if h.parsedPrivateKey != nil {
		defer h.privateKeyMu.RUnlock()
		return h.parsedPrivateKey, nil
	}
	h.privateKeyMu.RUnlock()

	h.privateKeyMu.Lock()
	defer h.privateKeyMu.Unlock()

	// Double-check after acquiring write lock
	if h.parsedPrivateKey != nil {
		return h.parsedPrivateKey, nil
	}

	var keyData []byte
	var err error

	// Try loading from content first
	if h.config.PrivateKey != "" {
		keyData = []byte(h.config.PrivateKey)
	} else if h.config.PrivateKeyPath != "" {
		// Fall back to loading from file
		keyData, err = os.ReadFile(h.config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key file: %v", err)
		}
	} else {
		return nil, fmt.Errorf("no private key provided")
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var key *rsa.PrivateKey

	switch block.Type {
	case "PRIVATE KEY":
		// PKCS#8 format
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %v", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	case "RSA PRIVATE KEY":
		// PKCS#1 format
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 private key: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	h.parsedPrivateKey = key
	return key, nil
}

// generateJWT creates a JWT token for GitHub App authentication
func (h *Handler) generateJWT() (string, error) {
	key, err := h.loadPrivateKey()
	if err != nil {
		return "", fmt.Errorf("load private key: %v", err)
	}

	// Create JWT with claims required by GitHub
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),                     // Issued at time
		"exp": now.Add(time.Minute * 10).Unix(), // JWT expires in 10 minutes
		"iss": h.config.AppID,                  // GitHub App's identifier
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign and get the complete encoded token as a string
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %v", err)
	}

	log.Printf("Generated JWT for GitHub App ID %s", h.config.AppID)
	return signedToken, nil
}