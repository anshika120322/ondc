<?php
/**
 * ONDC Ed25519 Signature Generator - PHP Implementation
 * 
 * Implements the ONDC protocol signature scheme for V3 API authentication.
 */

class ONDCSignature {
    private string $subscriberId;
    private string $uniqueKeyId;
    private string $privateKey;
    private string $publicKey;
    private string $publicKeyB64;
    
    /**
     * Initialize ONDC signature generator.
     *
     * @param string $subscriberId Unique subscriber ID
     * @param string $uniqueKeyId Unique key identifier
     * @param string $privateKeySeedHex 32-byte private key seed (hex string)
     */
    public function __construct(string $subscriberId, string $uniqueKeyId, string $privateKeySeedHex) {
        $this->subscriberId = $subscriberId;
        $this->uniqueKeyId = $uniqueKeyId;
        
        // Convert hex string to bytes
        $seed = hex2bin($privateKeySeedHex);
        if (strlen($seed) !== 32) {
            throw new Exception("Private key seed must be exactly 32 bytes, got " . strlen($seed));
        }
        
        // Generate Ed25519 key pair from seed
        $keypair = sodium_crypto_sign_seed_keypair($seed);
        $this->privateKey = sodium_crypto_sign_secretkey($keypair);
        $this->publicKey = sodium_crypto_sign_publickey($keypair);
        $this->publicKeyB64 = $this->getPublicKeyB64();
    }
    
    /**
     * Get DER/SPKI-encoded public key (base64).
     */
    private function getPublicKeyB64(): string {
        // SPKI/DER header for Ed25519 public key
        $spkiHeader = pack('C*',
            0x30, 0x2a,  // SEQUENCE, 42 bytes
            0x30, 0x05,  // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70,  // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00  // BIT STRING, 33 bytes (including 0x00 padding)
        );
        
        $spkiEncoded = $spkiHeader . $this->publicKey;
        return base64_encode($spkiEncoded);
    }
    
    /**
     * Create BLAKE2b-512 digest of request body.
     */
    private function createDigest($body): string {
        if ($body === null || $body === '' || $body === []) {
            $bodyBytes = '';
        } elseif (is_string($body)) {
            $bodyBytes = $body;
        } elseif (is_array($body) || is_object($body)) {
            // Sort keys recursively for consistent serialization
            $sortedBody = $this->sortArrayKeys($body);
            // Serialize with JSON (matches Python's json.dumps with separators=(', ', ': '), sort_keys=True)
            $json = json_encode($sortedBody, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            // Add spacing after JSON structure separators only (not within string values)
            $json = str_replace('":', '": ', $json);
            $json = str_replace(',"', ', "', $json);
            $json = str_replace('},{', '}, {', $json);
            $bodyBytes = $json;
        } else {
            throw new Exception('Body must be null, string, or array/object');
        }
        
        // Generate BLAKE2b-512 hash using sodium
        $hash = sodium_crypto_generichash($bodyBytes, '', 64);
        return base64_encode($hash);
    }
    
    /**
     * Create the signing string according to ONDC spec.
     */
    private function createSigningString(int $created, int $expires, string $digest): string {
        return "(created): {$created}\n(expires): {$expires}\ndigest: BLAKE-512={$digest}";
    }
    
    /**
     * Sign the signing string with Ed25519 private key.
     */
    private function signString(string $signingString): string {
        $signature = sodium_crypto_sign_detached($signingString, $this->privateKey);
        return base64_encode($signature);
    }
    
    /**
     * Generate complete Signature authorization header.
     *
     * @param mixed $body Request body (can be null, string, or array/object)
     * @param int|null $created Unix timestamp when signature was created (null for current time)
     * @param int|null $expires Unix timestamp when signature expires (null for created + 300)
     * @return array [authHeader, digestHeader]
     */
    public function generateSignatureHeader($body, ?int $created = null, ?int $expires = null): array {
        // Generate timestamps
        if ($created === null) {
            $created = time();
        }
        if ($expires === null) {
            // 60-second validity window (ONDC recommended: 30-60 seconds)
            $expires = $created + 60;
        }
        
        // Create digest
        $digest = $this->createDigest($body);
        $digestHeader = "BLAKE-512={$digest}";
        
        // Create signing string
        $signingString = $this->createSigningString($created, $expires, $digest);
        
        // Generate signature
        $signature = $this->signString($signingString);
        
        // Construct Signature header
        $keyId = "{$this->subscriberId}|{$this->uniqueKeyId}|ed25519";
        
        $authHeader = sprintf(
            'Signature keyId="%s",algorithm="ed25519",created="%d",expires="%d",headers="(created) (expires) digest",signature="%s"',
            $keyId, $created, $expires, $signature
        );
        
        return [$authHeader, $digestHeader];
    }
    
    /**
     * Get public key (base64).
     */
    public function getPublicKey(): string {
        return $this->publicKeyB64;
    }
    
    /**
     * Serialize body to JSON string matching the format used in digest calculation.
     * Use this when sending HTTP requests to ensure digest matches.
     */
    public function serializeBody($body): string {
        if ($body === null || $body === '' || $body === []) {
            return '';
        } elseif (is_string($body)) {
            return $body;
        } else {
            $sortedBody = $this->sortArrayKeys($body);
            $json = json_encode($sortedBody, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            // Add spacing after JSON structure separators to match digest format
            $json = str_replace('":', '": ', $json);
            $json = str_replace(',"', ', "', $json);
            $json = str_replace('},{', '}, {', $json);
            return $json;
        }
    }
    
    /**
     * Helper: Recursively sort array/object keys alphabetically for consistency.
     */
    private function sortArrayKeys($data) {
        if (!is_array($data) && !is_object($data)) {
            return $data;
        }
        
        $array = (array)$data;
        ksort($array);
        
        foreach ($array as $key => $value) {
            $array[$key] = $this->sortArrayKeys($value);
        }
        
        return $array;
    }
}
