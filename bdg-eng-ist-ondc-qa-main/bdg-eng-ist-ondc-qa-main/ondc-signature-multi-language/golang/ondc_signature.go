// ONDC Ed25519 Signature Generator - Go Implementation
//
// Implements the ONDC protocol signature scheme for V3 API authentication.

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// ONDCSignature handles ONDC signature generation
type ONDCSignature struct {
	SubscriberID string
	UniqueKeyID  string
	PrivateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	PublicKeyB64 string
}

// NewONDCSignature creates a new ONDC signature generator
func NewONDCSignature(subscriberID, uniqueKeyID, privateKeySeedHex string) (*ONDCSignature, error) {
	// Convert hex string to bytes
	seed, err := hex.DecodeString(privateKeySeedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex seed: %w", err)
	}

	if len(seed) != 32 {
		return nil, fmt.Errorf("private key seed must be exactly 32 bytes, got %d", len(seed))
	}

	// Generate Ed25519 key pair from seed
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	o := &ONDCSignature{
		SubscriberID: subscriberID,
		UniqueKeyID:  uniqueKeyID,
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
	}

	o.PublicKeyB64 = o.getPublicKeyB64()

	return o, nil
}

// getPublicKeyB64 returns DER/SPKI-encoded public key (base64)
func (o *ONDCSignature) getPublicKeyB64() string {
	// SPKI/DER header for Ed25519 public key
	spkiHeader := []byte{
		0x30, 0x2a, // SEQUENCE, 42 bytes
		0x30, 0x05, // SEQUENCE, 5 bytes
		0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
		0x03, 0x21, 0x00, // BIT STRING, 33 bytes (including 0x00 padding)
	}

	spkiEncoded := append(spkiHeader, o.PublicKey...)
	return base64.StdEncoding.EncodeToString(spkiEncoded)
}

// serializeJSON converts a body to JSON string with consistent formatting
func (o *ONDCSignature) serializeJSON(body interface{}) (string, error) {
	// Sort the object keys for consistent serialization
	sortedBody := sortMapKeys(body)

	// Marshal object to JSON with SetEscapeHTML(false) to match Python's ensure_ascii=False
	buf := new(strings.Builder)
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(sortedBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal body: %w", err)
	}

	// Remove trailing newline added by Encoder
	jsonStr := strings.TrimSuffix(buf.String(), "\n")

	// Add spaces after colons and commas to match Python format
	jsonStr = strings.ReplaceAll(jsonStr, "\":", "\": ")
	jsonStr = strings.ReplaceAll(jsonStr, ",\"", ", \"")
	jsonStr = strings.ReplaceAll(jsonStr, "},{", "}, {")

	return jsonStr, nil
}

// createDigest creates BLAKE2b-512 digest of request body
func (o *ONDCSignature) createDigest(body interface{}) (string, error) {
	var bodyBytes []byte

	if body == nil {
		bodyBytes = []byte{}
	} else if str, ok := body.(string); ok {
		bodyBytes = []byte(str)
	} else if b, ok := body.([]byte); ok {
		bodyBytes = b
	} else {
		jsonStr, err := o.serializeJSON(body)
		if err != nil {
			return "", err
		}
		bodyBytes = []byte(jsonStr)
	}

	// Generate BLAKE2b-512 hash
	hash := blake2b.Sum512(bodyBytes)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// createSigningString creates the signing string according to ONDC spec
func (o *ONDCSignature) createSigningString(created, expires int64, digest string) string {
	return fmt.Sprintf("(created): %d\n(expires): %d\ndigest: BLAKE-512=%s", created, expires, digest)
}

// signString signs the signing string with Ed25519 private key
func (o *ONDCSignature) signString(signingString string) string {
	signature := ed25519.Sign(o.PrivateKey, []byte(signingString))
	return base64.StdEncoding.EncodeToString(signature)
}

// GenerateSignatureHeader generates complete Signature authorization header
func (o *ONDCSignature) GenerateSignatureHeader(body interface{}, created, expires *int64) (string, string, error) {
	// Generate timestamps
	var createdTs, expiresTs int64
	if created == nil {
		createdTs = getCurrentTimestamp()
	} else {
		createdTs = *created
	}
	if expires == nil {
		// 60-second validity window (ONDC recommended: 30-60 seconds)
		expiresTs = createdTs + 60
	} else {
		expiresTs = *expires
	}

	// Create digest
	digest, err := o.createDigest(body)
	if err != nil {
		return "", "", err
	}
	digestHeader := fmt.Sprintf("BLAKE-512=%s", digest)

	// Create signing string
	signingString := o.createSigningString(createdTs, expiresTs, digest)

	// Generate signature
	signature := o.signString(signingString)

	// Construct Signature header
	keyID := fmt.Sprintf("%s|%s|ed25519", o.SubscriberID, o.UniqueKeyID)

	authHeader := fmt.Sprintf(
		`Signature keyId="%s",algorithm="ed25519",created="%d",expires="%d",headers="(created) (expires) digest",signature="%s"`,
		keyID, createdTs, expiresTs, signature,
	)

	return authHeader, digestHeader, nil
}

// GetPublicKey returns the public key (base64)
func (o *ONDCSignature) GetPublicKey() string {
	return o.PublicKeyB64
}

// SerializeBody serializes body to JSON string matching the format used in digest calculation
// Use this when sending HTTP requests to ensure digest matches
func (o *ONDCSignature) SerializeBody(body interface{}) (string, error) {
	if body == nil {
		return "", nil
	} else if str, ok := body.(string); ok {
		return str, nil
	} else {
		return o.serializeJSON(body)
	}
}

// Helper function to get current Unix timestamp
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// sortMapKeys recursively sorts map keys alphabetically for consistent JSON serialization
func sortMapKeys(obj interface{}) interface{} {
	switch v := obj.(type) {
	case map[string]interface{}:
		// Get all keys and sort them
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Create new map with sorted keys
		sorted := make(map[string]interface{})
		for _, k := range keys {
			sorted[k] = sortMapKeys(v[k])
		}
		return sorted
	case []interface{}:
		// Recursively sort arrays
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = sortMapKeys(item)
		}
		return result
	default:
		return obj
	}
}
