package com.ondc;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

/**
 * ONDC Ed25519 Signature Generator - Java Implementation
 * 
 * Implements the ONDC protocol signature scheme for V3 API authentication.
 */
public class ONDCSignature {
    private final String subscriberId;
    private final String uniqueKeyId;
    private final Ed25519PrivateKeyParameters privateKey;
    private final Ed25519PublicKeyParameters publicKey;
    private final String publicKeyB64;
    private final Gson gson;
    
    /**
     * Initialize ONDC signature generator.
     *
     * @param subscriberId   Unique subscriber ID
     * @param uniqueKeyId    Unique key identifier
     * @param privateKeySeed 32-byte private key seed (hex string)
     */
    public ONDCSignature(String subscriberId, String uniqueKeyId, String privateKeySeedHex) {
        this.subscriberId = subscriberId;
        this.uniqueKeyId = uniqueKeyId;
        
        // Convert hex string to bytes
        byte[] seed = hexStringToByteArray(privateKeySeedHex);
        if (seed.length != 32) {
            throw new IllegalArgumentException("Private key seed must be exactly 32 bytes");
        }
        
        // Generate Ed25519 key pair from seed
        this.privateKey = new Ed25519PrivateKeyParameters(seed, 0);
        this.publicKey = privateKey.generatePublicKey();
        this.publicKeyB64 = getPublicKeyB64();
        
        // Initialize Gson with specific formatting for consistent JSON
        this.gson = new GsonBuilder()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }
    
    /**
     * Get DER/SPKI-encoded public key (base64).
     */
    private String getPublicKeyB64() {
        byte[] rawPubKey = publicKey.getEncoded();
        
        // Wrap in SPKI/DER format (matching Python's SubjectPublicKeyInfo)
        byte[] spkiHeader = new byte[]{
            0x30, 0x2a,  // SEQUENCE, 42 bytes
            0x30, 0x05,  // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70,  // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00  // BIT STRING, 33 bytes (including 0x00 padding)
        };
        
        byte[] spkiEncoded = new byte[spkiHeader.length + rawPubKey.length];
        System.arraycopy(spkiHeader, 0, spkiEncoded, 0, spkiHeader.length);
        System.arraycopy(rawPubKey, 0, spkiEncoded, spkiHeader.length, rawPubKey.length);
        
        return Base64.getEncoder().encodeToString(spkiEncoded);
    }
    
    /**
     * Create BLAKE2b-512 digest of request body.
     */
    private String createDigest(Object body) {
        byte[] bodyBytes;
        
        if (body == null) {
            bodyBytes = new byte[0];
        } else if (body instanceof String) {
            bodyBytes = ((String) body).getBytes(StandardCharsets.UTF_8);
        } else if (body instanceof Map) {
            // Convert to TreeMap to sort keys alphabetically for consistency
            Map<String, Object> sortedBody = new TreeMap<>((Map<String, Object>) body);
            // Recursively sort nested maps
            sortedBody = sortMapRecursively(sortedBody);
            
            // Serialize with Gson and format to match Python's json.dumps(separators=(', ', ': '))
            String json = gson.toJson(sortedBody);
            // Add spaces after JSON structure separators only (not within string values)
            json = json.replaceAll("\":", "\": ").replaceAll(",\"", ", \"").replaceAll("\\},\\{" , "}, {");
            bodyBytes = json.getBytes(StandardCharsets.UTF_8);
        } else {
            throw new IllegalArgumentException("Body must be null, String, or Map");
        }
        
        // Generate BLAKE2b-512 hash
        Blake2bDigest digest = new Blake2bDigest(512);
        digest.update(bodyBytes, 0, bodyBytes.length);
        byte[] hash = new byte[64];
        digest.doFinal(hash, 0);
        
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * Create the signing string according to ONDC spec.
     */
    private String createSigningString(long created, long expires, String digest) {
        return String.format("(created): %d\n(expires): %d\ndigest: BLAKE-512=%s",
                           created, expires, digest);
    }
    
    /**
     * Sign the signing string with Ed25519 private key.
     */
    private String signString(String signingString) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        
        byte[] message = signingString.getBytes(StandardCharsets.UTF_8);
        signer.update(message, 0, message.length);
        byte[] signature = signer.generateSignature();
        
        return Base64.getEncoder().encodeToString(signature);
    }
    
    /**
     * Generate complete Signature authorization header.
     *
     * @param body    Request body (can be null, String, or Map)
     * @param created Unix timestamp when signature was created (null for current time)
     * @param expires Unix timestamp when signature expires (null for created + 300)
     * @return Authorization header string
     */
    public String generateSignatureHeader(Object body, Long created, Long expires) {
        // Generate timestamps
        if (created == null) {
            created = System.currentTimeMillis() / 1000;
        }
        if (expires == null) {
            // 60-second validity window (ONDC recommended: 30-60 seconds)
            expires = created + 60;
        }
        
        // Create digest
        String digest = createDigest(body);
        
        // Create signing string
        String signingString = createSigningString(created, expires, digest);
        
        // Generate signature
        String signature = signString(signingString);
        
        // Construct Signature header
        String keyId = String.format("%s|%s|ed25519", subscriberId, uniqueKeyId);
        
        return String.format(
            "Signature keyId=\"%s\",algorithm=\"ed25519\",created=\"%d\",expires=\"%d\",headers=\"(created) (expires) digest\",signature=\"%s\"",
            keyId, created, expires, signature
        );
    }
    
    /**
     * Generate Digest header.
     */
    public String generateDigestHeader(Object body) {
        return "BLAKE-512=" + createDigest(body);
    }
    
    /**
     * Get public key (base64).
     */
    public String getPublicKey() {
        return publicKeyB64;
    }
    
    /**
     * Serialize body to JSON string matching the format used in digest calculation.
     * Use this when sending HTTP requests to ensure digest matches.
     */
    public String serializeBody(Object body) {
        if (body == null || (body instanceof String && ((String) body).isEmpty())) {
            return "";
        } else if (body instanceof String) {
            return (String) body;
        } else if (body instanceof Map) {
            Map<String, Object> sortedBody = sortMapRecursively((Map<String, Object>) body);
            // Serialize with Gson and format to match Python's json.dumps(separators=(', ', ': '))
            String json = gson.toJson(sortedBody);
            // Add spaces after JSON structure separators only (not within string values)
            json = json.replaceAll("\":", "\": ").replaceAll(",\"", ", \"").replaceAll("\\},\\{", "}, {");
            return json;
        }
        return gson.toJson(body);
    }
    
    /**
     * Helper: Convert hex string to byte array.
     */
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Helper: Recursively sort maps to ensure consistent key ordering.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> sortMapRecursively(Map<String, Object> map) {
        Map<String, Object> sorted = new TreeMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map) {
                sorted.put(entry.getKey(), sortMapRecursively((Map<String, Object>) value));
            } else if (value instanceof java.util.List) {
                // Handle arrays - recursively sort maps inside array elements
                java.util.List<?> list = (java.util.List<?>) value;
                java.util.List<Object> sortedList = new java.util.ArrayList<>();
                for (Object item : list) {
                    if (item instanceof Map) {
                        sortedList.add(sortMapRecursively((Map<String, Object>) item));
                    } else {
                        sortedList.add(item);
                    }
                }
                sorted.put(entry.getKey(), sortedList);
            } else {
                sorted.put(entry.getKey(), value);
            }
        }
        return sorted;
    }
}
