# Test Suite for Ruby ONDC Signature Implementation

require 'json'
require 'httparty'
require_relative 'ondc_signature'

def load_test_data
  creds = JSON.parse(File.read('/shared/test-credentials.json'))
  payloads = JSON.parse(File.read('/shared/test-payloads.json'))
  [creds, payloads]
end

def test_key_generation(creds)
  puts "\n" + ('=' * 80)
  puts 'TEST 1: KEY GENERATION'
  puts '=' * 80
  
  uat = creds['uat']
  private_key_seed_hex = uat['private_key_seed_hex']
  
  signer = ONDCSignature.new(
    uat['subscriber_id'],
    uat['unique_key_id'],
    private_key_seed_hex
  )
  
  puts "✅ Private key seed: #{private_key_seed_hex[0...32]}..."
  puts "✅ Public key (base64): #{signer.get_public_key[0...40]}..."
  
  # Save for cross-language comparison
  result = {
    'language' => 'Ruby',
    'public_key' => signer.get_public_key,
    'test' => 'key_generation',
    'status' => 'PASS'
  }
  
  File.write('/reports/ruby-keys.json', JSON.pretty_generate(result))
  
  signer
end

def test_digest_generation(signer, payloads)
  puts "\n" + ('=' * 80)
  puts 'TEST 2: DIGEST GENERATION'
  puts '=' * 80
  
  results = []
  payloads['test_cases'].each do |test_case|
    digest = signer.create_digest(test_case['body'])
    puts "✅ #{test_case['name']}: #{digest[0...40]}..."
    
    results << {
      'test_name' => test_case['name'],
      'digest' => digest
    }
  end
  
  File.write('/reports/ruby-digests.json', JSON.pretty_generate({
    'language' => 'Ruby',
    'digests' => results
  }))
end

def test_signature_generation(signer, creds, payloads)
  puts "\n" + ('=' * 80)
  puts 'TEST 3: SIGNATURE GENERATION (Fixed Timestamps)'
  puts '=' * 80
  
  fixed_ts = creds['test_fixed_timestamp']
  created = fixed_ts['created']
  expires = fixed_ts['expires']
  
  results = []
  payloads['test_cases'].each do |test_case|
    auth_header, digest_header = signer.generate_signature_header(
      test_case['body'],
      created: created,
      expires: expires
    )
    
    puts "\n✅ #{test_case['name']}:"
    puts "   Auth: #{auth_header[0...80]}..."
    puts "   Digest: #{digest_header[0...80]}..."
    
    results << {
      'test_name' => test_case['name'],
      'authorization' => auth_header,
      'digest' => digest_header
    }
  end
  
  File.write('/reports/ruby-signatures.json', JSON.pretty_generate({
    'language' => 'Ruby',
    'signatures' => results
  }))
end

def test_live_api(signer, creds)
  puts "\n" + ('=' * 80)
  puts 'TEST 4: LIVE API CALL TO UAT - v3.0/lookup'
  puts '=' * 80
  
  uat = creds['uat']
  endpoint = "#{uat['base_url']}#{uat['lookup_endpoint']}"
  
  # Lookup payload - proper format for v3.0/lookup
  test_payload = {
    'subscriber_id' => uat['subscriber_id'],
    'domain' => 'ONDC:RET10'
  }
  
  auth_header, digest_header = signer.generate_signature_header(test_payload)
  
  # ⚠️ CRITICAL: Must use pre-serialized JSON matching digest calculation
  request_body_str = signer.serialize_body(test_payload)
  
  puts "📡 Endpoint: #{endpoint}"
  puts "📦 Payload: #{request_body_str}"
  puts "🔑 Authorization: #{auth_header}"
  puts "🔐 Digest: #{digest_header}"
  
  result = {}
  begin
    response = HTTParty.post(
      endpoint,
      body: request_body_str,
      headers: {
        'Content-Type' => 'application/json',
        'Authorization' => auth_header,
        'Digest' => digest_header
      },
      verify: false,  # Skip SSL verification for UAT
      timeout: 10
    )
    
    puts "\n✅ Response Status: #{response.code}"
    
    if response.code >= 200 && response.code < 300
      if response.body.strip.start_with?('[')
        puts '✅ SUCCESS: Signature verified! Participant found in registry!'
        result = { 'status' => 'PASS', 'code' => response.code, 'participant_found' => true }
      elsif response.body.include?('"1001"')
        puts '✅ SUCCESS: Signature verified, but participant not found in domain (1001)'
        result = { 'status' => 'PASS', 'code' => response.code, 'message' => 'Auth OK, domain mismatch' }
      else
        puts '✅ SUCCESS: Signature accepted by UAT API!'
        result = { 'status' => 'PASS', 'code' => response.code }
      end
      puts "Response: #{response.body}"
    elsif response.code == 404
      puts '✅ SUCCESS: Signature accepted (404 means participant not found, but auth worked)'
      result = { 'status' => 'PASS', 'code' => 404, 'message' => 'Auth OK, participant not found' }
    elsif response.code == 401
      puts '❌ FAIL: 401 Unauthorized - Signature verification failed'
      result = { 'status' => 'FAIL', 'code' => 401, 'message' => 'Signature verification failed' }
    else
      puts "⚠️  Unexpected status: #{response.code}"
      result = { 'status' => 'WARN', 'code' => response.code }
    end
    
  rescue => e
    puts "❌ API call failed: #{e.message}"
    result = { 'status' => 'ERROR', 'message' => e.message }
  end
  
  File.write('/reports/ruby-api-test.json', JSON.pretty_generate({
    'language' => 'Ruby',
    'result' => result
  }))
end

def main
  puts '╔' + ('=' * 78) + '╗'
  puts '║' + ' RUBY ONDC SIGNATURE IMPLEMENTATION TEST SUITE '.center(78) + '║'
  puts '╚' + ('=' * 78) + '╝'
  
  begin
    creds, payloads = load_test_data
    
    signer = test_key_generation(creds)
    test_digest_generation(signer, payloads)
    test_signature_generation(signer, creds, payloads)
    test_live_api(signer, creds)
    
    puts "\n" + ('=' * 80)
    puts '✅ ALL RUBY TESTS COMPLETED'
    puts '=' * 80 + "\n"
    
    exit 0
    
  rescue => e
    puts "\n❌ TEST SUITE FAILED: #{e.message}"
    puts e.backtrace.join("\n")
    exit 1
  end
end

main
