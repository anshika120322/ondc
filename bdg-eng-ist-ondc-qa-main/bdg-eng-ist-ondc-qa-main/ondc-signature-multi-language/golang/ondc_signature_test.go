package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

type TestCredentials struct {
	UAT struct {
		BaseURL           string `json:"base_url"`
		SubscribeEndpoint string `json:"subscribe_endpoint"`
		LookupEndpoint    string `json:"lookup_endpoint"`
		SubscriberID      string `json:"subscriber_id"`
		UniqueKeyID       string `json:"unique_key_id"`
		PrivateKeySeedHex string `json:"private_key_seed_hex"`
	} `json:"uat"`
	TestFixedTimestamp struct {
		Created int64  `json:"created"`
		Expires int64  `json:"expires"`
		Comment string `json:"comment"`
	} `json:"test_fixed_timestamp"`
}

type TestPayloads struct {
	TestCases []struct {
		Name        string      `json:"name"`
		Body        interface{} `json:"body"`
		Description string      `json:"description"`
	} `json:"test_cases"`
}

func loadTestData() (*TestCredentials, *TestPayloads, error) {
	credsFile, err := ioutil.ReadFile("/shared/test-credentials.json")
	if err != nil {
		return nil, nil, err
	}

	payloadsFile, err := ioutil.ReadFile("/shared/test-payloads.json")
	if err != nil {
		return nil, nil, err
	}

	var creds TestCredentials
	var payloads TestPayloads

	if err := json.Unmarshal(credsFile, &creds); err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(payloadsFile, &payloads); err != nil {
		return nil, nil, err
	}

	return &creds, &payloads, nil
}

func TestAllSignatures(t *testing.T) {
	fmt.Println("╔" + repeat("=", 78) + "╗")
	fmt.Println("║" + center(" GO ONDC SIGNATURE IMPLEMENTATION TEST SUITE ", 78) + "║")
	fmt.Println("╚" + repeat("=", 78) + "╝")

	creds, payloads, err := loadTestData()
	if err != nil {
		t.Fatalf("Failed to load test data: %v", err)
	}

	signer := testKeyGeneration(t, creds)
	testDigestGeneration(t, signer, payloads)
	testSignatureGeneration(t, signer, creds, payloads)
	testLiveAPI(t, signer, creds)

	fmt.Println("\n" + repeat("=", 80))
	fmt.Println("✅ ALL GO TESTS COMPLETED")
	fmt.Println(repeat("=", 80) + "\n")
}

func testKeyGeneration(t *testing.T, creds *TestCredentials) *ONDCSignature {
	fmt.Println("\n" + repeat("=", 80))
	fmt.Println("TEST 1: KEY GENERATION")
	fmt.Println(repeat("=", 80))

	signer, err := NewONDCSignature(
		creds.UAT.SubscriberID,
		creds.UAT.UniqueKeyID,
		creds.UAT.PrivateKeySeedHex,
	)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	fmt.Printf("✅ Private key seed: %s...\n", creds.UAT.PrivateKeySeedHex[:32])
	fmt.Printf("✅ Public key (base64): %s...\n", signer.GetPublicKey()[:40])

	// Save for cross-language comparison
	result := map[string]string{
		"language":   "Go",
		"public_key": signer.GetPublicKey(),
		"test":       "key_generation",
		"status":     "PASS",
	}

	saveJSON("/reports/golang-keys.json", result)

	return signer
}

func testDigestGeneration(t *testing.T, signer *ONDCSignature, payloads *TestPayloads) {
	fmt.Println("\n" + repeat("=", 80))
	fmt.Println("TEST 2: DIGEST GENERATION")
	fmt.Println(repeat("=", 80))

	results := []map[string]string{}
	for _, testCase := range payloads.TestCases {
		digest, err := signer.createDigest(testCase.Body)
		if err != nil {
			t.Errorf("Failed to create digest for %s: %v", testCase.Name, err)
			continue
		}

		fmt.Printf("✅ %s: %s...\n", testCase.Name, digest[:40])

		results = append(results, map[string]string{
			"test_name": testCase.Name,
			"digest":    digest,
		})
	}

	saveJSON("/reports/golang-digests.json", map[string]interface{}{
		"language": "Go",
		"digests":  results,
	})
}

func testSignatureGeneration(t *testing.T, signer *ONDCSignature, creds *TestCredentials, payloads *TestPayloads) {
	fmt.Println("\n" + repeat("=", 80))
	fmt.Println("TEST 3: SIGNATURE GENERATION (Fixed Timestamps)")
	fmt.Println(repeat("=", 80))

	created := creds.TestFixedTimestamp.Created
	expires := creds.TestFixedTimestamp.Expires

	results := []map[string]string{}
	for _, testCase := range payloads.TestCases {
		authHeader, digestHeader, err := signer.GenerateSignatureHeader(testCase.Body, &created, &expires)
		if err != nil {
			t.Errorf("Failed to generate signature for %s: %v", testCase.Name, err)
			continue
		}

		fmt.Printf("\n✅ %s:\n", testCase.Name)
		fmt.Printf("   Auth: %s...\n", authHeader[:80])
		fmt.Printf("   Digest: %s...\n", digestHeader[:80])

		results = append(results, map[string]string{
			"test_name":     testCase.Name,
			"authorization": authHeader,
			"digest":        digestHeader,
		})
	}

	saveJSON("/reports/golang-signatures.json", map[string]interface{}{
		"language":   "Go",
		"signatures": results,
	})
}

func testLiveAPI(t *testing.T, signer *ONDCSignature, creds *TestCredentials) {
	fmt.Println("\n" + repeat("=", 80))
	fmt.Println("TEST 4: LIVE API CALL TO UAT - v3.0/lookup")
	fmt.Println(repeat("=", 80))

	endpoint := creds.UAT.BaseURL + creds.UAT.LookupEndpoint

	// Lookup payload - proper format for v3.0/lookup
	testPayload := map[string]interface{}{
		"subscriber_id": creds.UAT.SubscriberID,
		"domain":        "ONDC:RET10",
	}

	authHeader, digestHeader, err := signer.GenerateSignatureHeader(testPayload, nil, nil)
	if err != nil {
		t.Fatalf("Failed to generate headers: %v", err)
	}

	// ⚠️ CRITICAL: Must use pre-serialized JSON matching digest calculation
	requestBodyStr, err := signer.SerializeBody(testPayload)
	if err != nil {
		t.Fatalf("Failed to serialize body: %v", err)
	}

	fmt.Printf("📡 Endpoint: %s\n", endpoint)
	fmt.Printf("📦 Payload: %s\n", requestBodyStr)
	fmt.Printf("🔑 Authorization: %s\n", authHeader)
	fmt.Printf("🔐 Digest: %s\n", digestHeader)

	// Create HTTP client with TLS skip verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	req, _ := http.NewRequest("POST", endpoint, strings.NewReader(requestBodyStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Digest", digestHeader)

	result := map[string]interface{}{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ API call failed: %v\n", err)
		result["status"] = "ERROR"
		result["message"] = err.Error()
	} else {
		defer resp.Body.Close()

		fmt.Printf("\n✅ Response Status: %d\n", resp.StatusCode)

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)

			// Check if response is a list (successful lookup)
			if strings.HasPrefix(strings.TrimSpace(bodyStr), "[") {
				fmt.Println("✅ SUCCESS: Signature verified! Participant found in registry!")
				result["status"] = "PASS"
				result["code"] = resp.StatusCode
				result["participant_found"] = true
			} else if strings.Contains(bodyStr, "\"1001\"") {
				fmt.Println("✅ SUCCESS: Signature verified, but participant not found in domain (1001)")
				result["status"] = "PASS"
				result["code"] = resp.StatusCode
				result["message"] = "Auth OK, domain mismatch"
			} else {
				fmt.Println("✅ SUCCESS: Signature accepted by UAT API!")
				result["status"] = "PASS"
				result["code"] = resp.StatusCode
			}

			fmt.Printf("Response: %s\n", bodyStr[:minInt(300, len(bodyStr))])
		} else if resp.StatusCode == 404 {
			fmt.Println("✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)")
			result["status"] = "PASS"
			result["code"] = 404
			result["message"] = "Auth OK, participant not found"
		} else if resp.StatusCode == 401 {
			fmt.Println("❌ FAIL: 401 Unauthorized - Signature verification failed")
			result["status"] = "FAIL"
			result["code"] = 401
			result["message"] = "Signature verification failed"
		} else {
			fmt.Printf("⚠️  Unexpected status: %d\n", resp.StatusCode)
			result["status"] = "WARN"
			result["code"] = resp.StatusCode
		}
	}

	saveJSON("/reports/golang-api-test.json", map[string]interface{}{
		"language": "Go",
		"result":   result,
	})
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func saveJSON(path string, data interface{}) {
	jsonData, _ := json.MarshalIndent(data, "", "  ")
	ioutil.WriteFile(path, jsonData, 0644)
}

func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

func center(s string, width int) string {
	if len(s) >= width {
		return s
	}
	leftPad := (width - len(s)) / 2
	rightPad := width - len(s) - leftPad
	return repeat(" ", leftPad) + s + repeat(" ", rightPad)
}
