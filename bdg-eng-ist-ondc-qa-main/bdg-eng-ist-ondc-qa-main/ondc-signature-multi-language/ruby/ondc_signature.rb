# ONDC Ed25519 Signature Generator - Ruby Implementation
#
# Implements the ONDC protocol signature scheme for V3 API authentication.

require 'ed25519'
require 'rbnacl'
require 'base64'
require 'json'

class ONDCSignature
  attr_reader :subscriber_id, :unique_key_id, :public_key_b64
  
  # Initialize ONDC signature generator.
  #
  # @param subscriber_id [String] Unique subscriber ID
  # @param unique_key_id [String] Unique key identifier
  # @param private_key_seed_hex [String] 32-byte private key seed (hex string)
  def initialize(subscriber_id, unique_key_id, private_key_seed_hex)
    @subscriber_id = subscriber_id
    @unique_key_id = unique_key_id
    
    # Convert hex string to bytes
    seed = [private_key_seed_hex].pack('H*')
    raise ArgumentError, "Private key seed must be exactly 32 bytes, got #{seed.length}" unless seed.length == 32
    
    # Generate Ed25519 key pair from seed
    @signing_key = Ed25519::SigningKey.new(seed)
    @verify_key = @signing_key.verify_key
    @public_key_b64 = get_public_key_b64
  end
  
  # Get DER/SPKI-encoded public key (base64).
  def get_public_key_b64
    # SPKI/DER header for Ed25519 public key
    spki_header = [
      0x30, 0x2a,  # SEQUENCE, 42 bytes
      0x30, 0x05,  # SEQUENCE, 5 bytes
      0x06, 0x03, 0x2b, 0x65, 0x70,  # OID 1.3.101.112 (Ed25519)
      0x03, 0x21, 0x00  # BIT STRING, 33 bytes (including 0x00 padding)
    ].pack('C*')
    
    spki_encoded = spki_header + @verify_key.to_bytes
    Base64.strict_encode64(spki_encoded)
  end
  
  # Create BLAKE2b-512 digest of request body.
  def create_digest(body)
    if body.nil? || body == '' || body == {}
      body_bytes = ''
    elsif body.is_a?(String)
      body_bytes = body
    elsif body.is_a?(Hash) || body.is_a?(Array)
      # Sort hash keys recursively for consistent serialization
      sorted_body = sort_hash_keys(body)
      # Serialize with JSON (matches Python's json.dumps with separators=(', ', ': '), sort_keys=True)
      json_str = JSON.generate(sorted_body)
      # Add spacing after JSON structure separators only (not within string values)
      json_str = json_str.gsub('":', '": ').gsub(',"', ', "').gsub('},{', '}, {')
      body_bytes = json_str
    else
      raise ArgumentError, 'Body must be nil, string, hash, or array'
    end
    
    # Generate BLAKE2b-512 hash
    hash = RbNaCl::Hash.blake2b(body_bytes, digest_size: 64)
    Base64.strict_encode64(hash)
  end
  
  # Create the signing string according to ONDC spec.
  def create_signing_string(created, expires, digest)
    "(created): #{created}\n(expires): #{expires}\ndigest: BLAKE-512=#{digest}"
  end
  
  # Sign the signing string with Ed25519 private key.
  def sign_string(signing_string)
    signature = @signing_key.sign(signing_string.encode('UTF-8'))
    Base64.strict_encode64(signature)
  end
  
  # Generate complete Signature authorization header.
  #
  # @param body [Object] Request body (can be nil, string, hash, or array)
  # @param created [Integer, nil] Unix timestamp when signature was created (nil for current time)
  # @param expires [Integer, nil] Unix timestamp when signature expires (nil for created + 300)
  # @return [Array<String>] [auth_header, digest_header]
  def generate_signature_header(body, created: nil, expires: nil)
    # Generate timestamps
    if created.nil?
      created = Time.now.to_i
    end
    if expires.nil?
      # 60-second validity window (ONDC recommended: 30-60 seconds)
      expires = created + 60
    end
    
    # Create digest
    digest = create_digest(body)
    digest_header = "BLAKE-512=#{digest}"
    
    # Create signing string
    signing_string = create_signing_string(created, expires, digest)
    
    # Generate signature
    signature = sign_string(signing_string)
    
    # Construct Signature header
    key_id = "#{@subscriber_id}|#{@unique_key_id}|ed25519"
    
    auth_header = %(Signature keyId="#{key_id}",algorithm="ed25519",created="#{created}",expires="#{expires}",headers="(created) (expires) digest",signature="#{signature}")
    
    [auth_header, digest_header]
  end
  
  # Get public key (base64).
  def get_public_key
    @public_key_b64
  end
  
  # Serialize body to JSON string matching the format used in digest calculation
  # Use this when sending HTTP requests to ensure digest matches
  def serialize_body(body)
    return '' if body.nil? || body == '' || body == []
    return body if body.is_a?(String)
    
    sorted_body = sort_hash_keys(body)
    json = JSON.generate(sorted_body)
    # Add spacing after JSON structure separators to match digest format
    json.gsub!('":', '": ')
    json.gsub!(',"', ', "')
    json.gsub!('},{', '}, {')
    json
  end
  
  private
  
  # Helper: Recursively sort hash keys alphabetically for consistency.
  def sort_hash_keys(data)
    case data
    when Hash
      sorted = {}
      data.keys.sort.each do |key|
        sorted[key] = sort_hash_keys(data[key])
      end
      sorted
    when Array
      data.map { |item| sort_hash_keys(item) }
    else
      data
    end
  end
end
