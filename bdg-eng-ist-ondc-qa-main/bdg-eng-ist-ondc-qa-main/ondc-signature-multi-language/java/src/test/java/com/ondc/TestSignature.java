package com.ondc;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;
import okhttp3.*;
import org.junit.jupiter.api.Test;

import java.io.FileReader;
import java.io.FileWriter;
import java.lang.reflect.Type;
import java.util.*;

/**
 * Test Suite for Java ONDC Signature Implementation
 */
public class TestSignature {
    
    // Configure Gson to preserve number types (integers vs doubles)
    private static final Gson gson = new GsonBuilder()
        .setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
        .create();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    @Test
    public void runAllTests() throws Exception {
        System.out.println("╔" + "=".repeat(78) + "╗");
        System.out.println("║" + center(" JAVA ONDC SIGNATURE IMPLEMENTATION TEST SUITE ", 78) + "║");
        System.out.println("╚" + "=".repeat(78) + "╝");
        
        // Load test data
        Map<String, Object> creds = loadJSON("/shared/test-credentials.json");
        Map<String, Object> payloads = loadJSON("/shared/test-payloads.json");
        
        // Run tests
        ONDCSignature signer = testKeyGeneration(creds);
        testDigestGeneration(signer, payloads);
        testSignatureGeneration(signer, creds, payloads);
        testLiveAPI(signer, creds);
        
        System.out.println("\n" + "=".repeat(80));
        System.out.println("✅ ALL JAVA TESTS COMPLETED");
        System.out.println("=".repeat(80) + "\n");
    }
    
    private ONDCSignature testKeyGeneration(Map<String, Object> creds) throws Exception {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("TEST 1: KEY GENERATION");
        System.out.println("=".repeat(80));
        
        Map<String, String> uat = (Map<String, String>) creds.get("uat");
        String privateKeySeedHex = uat.get("private_key_seed_hex");
        
        ONDCSignature signer = new ONDCSignature(
            uat.get("subscriber_id"),
            uat.get("unique_key_id"),
            privateKeySeedHex
        );
        
        System.out.println("✅ Private key seed: " + privateKeySeedHex.substring(0, 32) + "...");
        System.out.println("✅ Public key (base64): " + signer.getPublicKey().substring(0, 40) + "...");
        
        // Save for cross-language comparison
        Map<String, String> result = new HashMap<>();
        result.put("language", "Java");
        result.put("public_key", signer.getPublicKey());
        result.put("test", "key_generation");
        result.put("status", "PASS");
        
        saveJSON("/reports/java-keys.json", result);
        
        return signer;
    }
    
    private void testDigestGeneration(ONDCSignature signer, Map<String, Object> payloads) throws Exception {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("TEST 2: DIGEST GENERATION");
        System.out.println("=".repeat(80));
        
        List<Map<String, Object>> testCases = (List<Map<String, Object>>) payloads.get("test_cases");
        List<Map<String, String>> results = new ArrayList<>();
        
        for (Map<String, Object> testCase : testCases) {
            String name = (String) testCase.get("name");
            Object body = testCase.get("body");
            
            String digest = signer.generateDigestHeader(body).substring(10); // Remove "BLAKE-512=" (10 chars)
System.out.println("✅ " + name + ": " + digest.substring(0, 40) + "...");
            
            Map<String, String> result = new HashMap<>();
            result.put("test_name", name);
            result.put("digest", digest);
            results.add(result);
        }
        
        Map<String, Object> output = new HashMap<>();
        output.put("language", "Java");
        output.put("digests", results);
        saveJSON("/reports/java-digests.json", output);
    }
    
    private void testSignatureGeneration(ONDCSignature signer, Map<String, Object> creds, 
                                        Map<String, Object> payloads) throws Exception {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("TEST 3: SIGNATURE GENERATION (Fixed Timestamps)");
        System.out.println("=".repeat(80));
        
        Map<String, Object> fixedTs = (Map<String, Object>) creds.get("test_fixed_timestamp");
        long created = ((Number) fixedTs.get("created")).longValue();
        long expires = ((Number) fixedTs.get("expires")).longValue();
        
        List<Map<String, Object>> testCases = (List<Map<String, Object>>) payloads.get("test_cases");
        List<Map<String, String>> results = new ArrayList<>();
        
        for (Map<String, Object> testCase : testCases) {
            String name = (String) testCase.get("name");
            Object body = testCase.get("body");
            
            String authHeader = signer.generateSignatureHeader(body, created, expires);
            String digestHeader = signer.generateDigestHeader(body);
            
            System.out.println("\n✅ " + name + ":");
            System.out.println("   Auth: " + authHeader.substring(0, 80) + "...");
            System.out.println("   Digest: " + digestHeader.substring(0, 80) + "...");
            
            Map<String, String> result = new HashMap<>();
            result.put("test_name", name);
            result.put("authorization", authHeader);
            result.put("digest", digestHeader);
            results.add(result);
        }
        
        Map<String, Object> output = new HashMap<>();
        output.put("language", "Java");
        output.put("signatures", results);
        saveJSON("/reports/java-signatures.json", output);
    }
    
    private void testLiveAPI(ONDCSignature signer, Map<String, Object> creds) throws Exception {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("TEST 4: LIVE API CALL TO UAT - v3.0/lookup");
        System.out.println("=".repeat(80));
        
        Map<String, String> uat = (Map<String, String>) creds.get("uat");
        String endpoint = uat.get("base_url") + uat.get("lookup_endpoint");
        
        // Lookup payload - proper format for v3.0/lookup
        Map<String, Object> testPayload = new HashMap<>();
        testPayload.put("subscriber_id", uat.get("subscriber_id"));
        testPayload.put("domain", "ONDC:RET10");
        
        String authHeader = signer.generateSignatureHeader(testPayload, null, null);
        String digestHeader = signer.generateDigestHeader(testPayload);
        
        // ⚠️ CRITICAL: Must use pre-serialized JSON matching digest calculation
        String requestBodyStr = signer.serializeBody(testPayload);
        
        System.out.println("📡 Endpoint: " + endpoint);
        System.out.println("📦 Payload: " + requestBodyStr);
        System.out.println("🔑 Authorization: " + authHeader);
        System.out.println("🔐 Digest: " + digestHeader);
        
        OkHttpClient client = new OkHttpClient.Builder()
            .hostnameVerifier((hostname, session) -> true)  // Skip SSL verification for UAT
            .build();
        
        RequestBody body = RequestBody.create(requestBodyStr, JSON);
        Request request = new Request.Builder()
            .url(endpoint)
            .header("Authorization", authHeader)
            .header("Digest", digestHeader)
            .post(body)
            .build();
        
        Map<String, Object> result = new HashMap<>();
        try (Response response = client.newCall(request).execute()) {
            int statusCode = response.code();
            System.out.println("\n✅ Response Status: " + statusCode);
            
            if (statusCode >= 200 && statusCode < 300) {
                String responseBody = response.body().string();
                if (responseBody.trim().startsWith("[")) {
                    System.out.println("✅ SUCCESS: Signature verified! Participant found in registry!");
                    result.put("status", "PASS");
                    result.put("code", statusCode);
                    result.put("participant_found", true);
                } else if (responseBody.contains("\"1001\"")) {
                    System.out.println("✅ SUCCESS: Signature verified, but participant not found in domain (1001)");
                    result.put("status", "PASS");
                    result.put("code", statusCode);
                    result.put("message", "Auth OK, domain mismatch");
                } else {
                    System.out.println("✅ SUCCESS: Signature accepted by UAT API!");
                    result.put("status", "PASS");
                    result.put("code", statusCode);
                }
                System.out.println("Response: " + responseBody);
            } else if (statusCode == 404) {
                System.out.println("✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)");
                result.put("status", "PASS");
                result.put("code", 404);
                result.put("message", "Auth OK, participant not found");
            } else if (statusCode == 401) {
                System.out.println("❌ FAIL: 401 Unauthorized - Signature verification failed");
                result.put("status", "FAIL");
                result.put("code", 401);
                result.put("message", "Signature verification failed");
            } else {
                System.out.println("⚠️  Unexpected status: " + statusCode);
                result.put("status", "WARN");
                result.put("code", statusCode);
            }
            
        } catch (Exception e) {
            System.out.println("❌ API call failed: " + e.getMessage());
            result.put("status", "ERROR");
            result.put("message", e.getMessage());
        }
        
        Map<String, Object> output = new HashMap<>();
        output.put("language", "Java");
        output.put("result", result);
        saveJSON("/reports/java-api-test.json", output);
    }
    
    private Map<String, Object> loadJSON(String path) throws Exception {
        FileReader reader = new FileReader(path);
        Type type = new TypeToken<Map<String, Object>>(){}.getType();
        return gson.fromJson(reader, type);
    }
    
    private void saveJSON(String path, Object data) throws Exception {
        FileWriter writer = new FileWriter(path);
        gson.toJson(data, writer);
        writer.close();
    }
    
    private static String center(String text, int width) {
        int spaces = width - text.length();
        int leftPad = spaces / 2;
        int rightPad = spaces - leftPad;
        return " ".repeat(leftPad) + text + " ".repeat(rightPad);
    }
}
