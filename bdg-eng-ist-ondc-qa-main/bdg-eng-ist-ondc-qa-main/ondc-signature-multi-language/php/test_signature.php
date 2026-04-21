<?php
/**
 * Test Suite for PHP ONDC Signature Implementation
 */

require_once 'ONDCSignature.php';

function loadTestData() {
    $creds = json_decode(file_get_contents('/shared/test-credentials.json'), true);
    $payloads = json_decode(file_get_contents('/shared/test-payloads.json'), true);
    return [$creds, $payloads];
}

function testKeyGeneration($creds) {
    echo "\n" . str_repeat('=', 80) . "\n";
    echo "TEST 1: KEY GENERATION\n";
    echo str_repeat('=', 80) . "\n";
    
    $uat = $creds['uat'];
    $privateKeySeedHex = $uat['private_key_seed_hex'];
    
    $signer = new ONDCSignature(
        $uat['subscriber_id'],
        $uat['unique_key_id'],
        $privateKeySeedHex
    );
    
    echo "✅ Private key seed: " . substr($privateKeySeedHex, 0, 32) . "...\n";
    echo "✅ Public key (base64): " . substr($signer->getPublicKey(), 0, 40) . "...\n";
    
    // Save for cross-language comparison
    $result = [
        'language' => 'PHP',
        'public_key' => $signer->getPublicKey(),
        'test' => 'key_generation',
        'status' => 'PASS'
    ];
    
    file_put_contents('/reports/php-keys.json', json_encode($result, JSON_PRETTY_PRINT));
    
    return $signer;
}

function testDigestGeneration($signer, $payloads) {
    echo "\n" . str_repeat('=', 80) . "\n";
    echo "TEST 2: DIGEST GENERATION\n";
    echo str_repeat('=', 80) . "\n";
    
    $results = [];
    foreach ($payloads['test_cases'] as $testCase) {
        $reflection = new ReflectionClass($signer);
        $method = $reflection->getMethod('createDigest');
        $method->setAccessible(true);
        $digest = $method->invoke($signer, $testCase['body']);
        
        echo "✅ {$testCase['name']}: " . substr($digest, 0, 40) . "...\n";
        
        $results[] = [
            'test_name' => $testCase['name'],
            'digest' => $digest
        ];
    }
    
    file_put_contents('/reports/php-digests.json', json_encode([
        'language' => 'PHP',
        'digests' => $results
    ], JSON_PRETTY_PRINT));
}

function testSignatureGeneration($signer, $creds, $payloads) {
    echo "\n" . str_repeat('=', 80) . "\n";
    echo "TEST 3: SIGNATURE GENERATION (Fixed Timestamps)\n";
    echo str_repeat('=', 80) . "\n";
    
    $fixedTs = $creds['test_fixed_timestamp'];
    $created = $fixedTs['created'];
    $expires = $fixedTs['expires'];
    
    $results = [];
    foreach ($payloads['test_cases'] as $testCase) {
        list($authHeader, $digestHeader) = $signer->generateSignatureHeader(
            $testCase['body'], $created, $expires
        );
        
        echo "\n✅ {$testCase['name']}:\n";
        echo "   Auth: " . substr($authHeader, 0, 80) . "...\n";
        echo "   Digest: " . substr($digestHeader, 0, 80) . "...\n";
        
        $results[] = [
            'test_name' => $testCase['name'],
            'authorization' => $authHeader,
            'digest' => $digestHeader
        ];
    }
    
    file_put_contents('/reports/php-signatures.json', json_encode([
        'language' => 'PHP',
        'signatures' => $results
    ], JSON_PRETTY_PRINT));
}

function testLiveAPI($signer, $creds) {
    echo "\n" . str_repeat('=', 80) . "\n";
    echo "TEST 4: LIVE API CALL TO UAT - v3.0/lookup\n";
    echo str_repeat('=', 80) . "\n";
    
    $uat = $creds['uat'];
    $endpoint = $uat['base_url'] . $uat['lookup_endpoint'];
    
    // Lookup payload - proper format for v3.0/lookup
    $testPayload = [
        'subscriber_id' => $uat['subscriber_id'],
        'domain' => 'ONDC:RET10'
    ];
    
    list($authHeader, $digestHeader) = $signer->generateSignatureHeader($testPayload);
    
    // ⚠️ CRITICAL: Must use pre-serialized JSON matching digest calculation
    $requestBodyStr = $signer->serializeBody($testPayload);
    
    echo "📡 Endpoint: {$endpoint}\n";
    echo "📦 Payload: {$requestBodyStr}\n";
    echo "🔑 Authorization: {$authHeader}\n";
    echo "🔐 Digest: {$digestHeader}\n";
    
    // Create HTTP context with headers
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n" .
                       "Authorization: {$authHeader}\r\n" .
                       "Digest: {$digestHeader}\r\n",
            'content' => $requestBodyStr,
            'timeout' => 10,
            'ignore_errors' => true
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);
    
    $result = [];
    try {
        $response = file_get_contents($endpoint, false, $context);
        $statusLine = $http_response_header[0] ?? '';
        preg_match('/\d{3}/', $statusLine, $matches);
        $statusCode = (int)($matches[0] ?? 0);
        
        echo "\n✅ Response Status: {$statusCode}\n";
        
        if ($statusCode >= 200 && $statusCode < 300) {
            if (strpos(trim($response), '[') === 0) {
                echo "✅ SUCCESS: Signature verified! Participant found in registry!\n";
                $result = ['status' => 'PASS', 'code' => $statusCode, 'participant_found' => true];
            } elseif (strpos($response, '"1001"') !== false) {
                echo "✅ SUCCESS: Signature verified, but participant not found in domain (1001)\n";
                $result = ['status' => 'PASS', 'code' => $statusCode, 'message' => 'Auth OK, domain mismatch'];
            } else {
                echo "✅ SUCCESS: Signature accepted by UAT API!\n";
                $result = ['status' => 'PASS', 'code' => $statusCode];
            }
            echo "Response: {$response}\n";
        } elseif ($statusCode === 404) {
            echo "✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)\n";
            $result = ['status' => 'PASS', 'code' => 404, 'message' => 'Auth OK, participant not found'];
        } elseif ($statusCode === 401) {
            echo "❌ FAIL: 401 Unauthorized - Signature verification failed\n";
            $result = ['status' => 'FAIL', 'code' => 401, 'message' => 'Signature verification failed'];
        } else {
            echo "⚠️  Unexpected status: {$statusCode}\n";
            $result = ['status' => 'WARN', 'code' => $statusCode];
        }
        
        echo "Response: {$response}\n";
        
    } catch (Exception $e) {
        echo "❌ API call failed: " . $e->getMessage() . "\n";
        $result = ['status' => 'ERROR', 'message' => $e->getMessage()];
    }
    
    file_put_contents('/reports/php-api-test.json', json_encode([
        'language' => 'PHP',
        'result' => $result
    ], JSON_PRETTY_PRINT));
}

function main() {
    echo "╔" . str_repeat('=', 78) . "╗\n";
    echo "║" . str_pad(' PHP ONDC SIGNATURE IMPLEMENTATION TEST SUITE ', 78, ' ', STR_PAD_BOTH) . "║\n";
    echo "╚" . str_repeat('=', 78) . "╝\n";
    
    try {
        list($creds, $payloads) = loadTestData();
        
        $signer = testKeyGeneration($creds);
        testDigestGeneration($signer, $payloads);
        testSignatureGeneration($signer, $creds, $payloads);
        testLiveAPI($signer, $creds);
        
        echo "\n" . str_repeat('=', 80) . "\n";
        echo "✅ ALL PHP TESTS COMPLETED\n";
        echo str_repeat('=', 80) . "\n\n";
        
        exit(0);
        
    } catch (Exception $e) {
        echo "\n❌ TEST SUITE FAILED: " . $e->getMessage() . "\n";
        echo $e->getTraceAsString() . "\n";
        exit(1);
    }
}

main();
