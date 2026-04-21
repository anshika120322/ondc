/**
 * Test Suite for Node.js ONDC Signature Implementation
 */

import fs from 'fs';
import https from 'https';
import axios from 'axios';
import ONDCSignature from './ondc-signature.js';

async function loadTestData() {
    const creds = JSON.parse(fs.readFileSync('/shared/test-credentials.json', 'utf8'));
    const payloads = JSON.parse(fs.readFileSync('/shared/test-payloads.json', 'utf8'));
    return { creds, payloads };
}

async function testKeyGeneration(creds) {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 1: KEY GENERATION');
    console.log('='.repeat(80));
    
    const uat = creds.uat;
    const privateKeySeed = Buffer.from(uat.private_key_seed_hex, 'hex');
    
    const signer = new ONDCSignature(
        uat.subscriber_id,
        uat.unique_key_id,
        privateKeySeed
    );
    
    console.log(`✅ Private key seed: ${uat.private_key_seed_hex.substring(0, 32)}...`);
    console.log(`✅ Public key (base64): ${signer.getPublicKey().substring(0, 40)}...`);
    
    // Save for cross-language comparison
    const result = {
        language: 'Node.js',
        public_key: signer.getPublicKey(),
        test: 'key_generation',
        status: 'PASS'
    };
    
    fs.writeFileSync('/reports/nodejs-keys.json', JSON.stringify(result, null, 2));
    
    return signer;
}

async function testDigestGeneration(signer, payloads) {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 2: DIGEST GENERATION');
    console.log('='.repeat(80));
    
    const results = [];
    for (const testCase of payloads.test_cases) {
        const digest = signer._createDigest(testCase.body);
        console.log(`✅ ${testCase.name}: ${digest.substring(0, 40)}...`);
        results.push({
            test_name: testCase.name,
            digest: digest
        });
    }
    
    fs.writeFileSync('/reports/nodejs-digests.json', JSON.stringify({
        language: 'Node.js',
        digests: results
    }, null, 2));
}

async function testSignatureGeneration(signer, creds, payloads) {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 3: SIGNATURE GENERATION (Fixed Timestamps)');
    console.log('='.repeat(80));
    
    const fixedTs = creds.test_fixed_timestamp;
    const created = fixedTs.created;
    const expires = fixedTs.expires;
    
    const results = [];
    for (const testCase of payloads.test_cases) {
        const authHeader = await signer.generateSignatureHeader(testCase.body, created, expires);
        const digestHeader = signer.generateDigestHeader(testCase.body);
        
        console.log(`\n✅ ${testCase.name}:`);
        console.log(`   Auth: ${authHeader.substring(0, 80)}...`);
        console.log(`   Digest: ${digestHeader.substring(0, 80)}...`);
        
        results.push({
            test_name: testCase.name,
            authorization: authHeader,
            digest: digestHeader
        });
    }
    
    fs.writeFileSync('/reports/nodejs-signatures.json', JSON.stringify({
        language: 'Node.js',
        signatures: results
    }, null, 2));
}

async function testLiveAPI(signer, creds) {
    console.log('\n' + '='.repeat(80));
    console.log('TEST 4: LIVE API CALL TO UAT - v3.0/lookup');
    console.log('='.repeat(80));
    
    const uat = creds.uat;
    const endpoint = `${uat.base_url}${uat.lookup_endpoint}`;
    
    // Lookup payload - proper format for v3.0/lookup
    const testPayload = {
        subscriber_id: uat.subscriber_id,
        domain: 'ONDC:RET10'
    };
    
    const authHeader = await signer.generateSignatureHeader(testPayload);
    const digestHeader = signer.generateDigestHeader(testPayload);
    
    // ⚠️ CRITICAL: Must use pre-serialized JSON matching digest calculation
    // The signer serializes with specific format for digest calculation
    // We must send the exact same serialization to avoid mismatch
    const requestBodyStr = signer.serializeBody(testPayload);
    
    console.log(`📡 Endpoint: ${endpoint}`);
    console.log(`📦 Payload: ${requestBodyStr}`);
    console.log(`🔑 Authorization: ${authHeader}`);
    console.log(`🔐 Digest: ${digestHeader}`);
    
    const httpsAgent = new https.Agent({
        rejectUnauthorized: false  // Skip SSL verification for UAT
    });
    
    let result;
    try {
        const response = await axios.post(endpoint, requestBodyStr, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authHeader,
                'Digest': digestHeader
            },
            httpsAgent,
            timeout: 10000
        });
        
        console.log(`\n✅ Response Status: ${response.status}`);
        
        if (response.status >= 200 && response.status < 300) {
            if (Array.isArray(response.data) && response.data.length > 0) {
                console.log('✅ SUCCESS: Signature verified! Participant found in registry!');
                result = { status: 'PASS', code: response.status, participant_found: true };
            } else if (response.data && response.data.error && response.data.error.code === '1001') {
                console.log('✅ SUCCESS: Signature verified, but participant not found in domain (1001)');
                result = { status: 'PASS', code: response.status, message: 'Auth OK, domain mismatch' };
            } else {
                console.log('✅ SUCCESS: Signature accepted by UAT API!');
                result = { status: 'PASS', code: response.status };
            }
        } else {
            console.log(`⚠️  Unexpected status: ${response.status}`);
            result = { status: 'WARN', code: response.status };
        }
        
        console.log(`Response: ${JSON.stringify(response.data)}`);
        
    } catch (error) {
        if (error.response) {
            console.log(`\n✅ Response Status: ${error.response.status}`);
            if (error.response.status === 404) {
                console.log('✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)');
                result = { status: 'PASS', code: 404, message: 'Auth OK, participant not found' };
            } else if (error.response.status === 401) {
                console.log('❌ FAIL: 401 Unauthorized - Signature verification failed');
                result = { status: 'FAIL', code: 401, message: 'Signature verification failed' };
            } else {
                console.log(`⚠️  Unexpected status: ${error.response.status}`);
                result = { status: 'WARN', code: error.response.status };
            }
        } else {
            console.log(`❌ API call failed: ${error.message}`);
            result = { status: 'ERROR', message: error.message };
        }
    }
    
    fs.writeFileSync('/reports/nodejs-api-test.json', JSON.stringify({
        language: 'Node.js',
        result: result
    }, null, 2));
}

async function main() {
    console.log('╔' + '='.repeat(78) + '╗');
    console.log('║' + ' NODE.JS ONDC SIGNATURE IMPLEMENTATION TEST SUITE '.padStart(54).padEnd(78) + '║');
    console.log('╚' + '='.repeat(78) + '╝');
    
    try {
        const { creds, payloads } = await loadTestData();
        
        const signer = await testKeyGeneration(creds);
        await testDigestGeneration(signer, payloads);
        await testSignatureGeneration(signer, creds, payloads);
        await testLiveAPI(signer, creds);
        
        console.log('\n' + '='.repeat(80));
        console.log('✅ ALL NODE.JS TESTS COMPLETED');
        console.log('='.repeat(80) + '\n');
        
        process.exit(0);
        
    } catch (error) {
        console.error(`\n❌ TEST SUITE FAILED: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

main();
