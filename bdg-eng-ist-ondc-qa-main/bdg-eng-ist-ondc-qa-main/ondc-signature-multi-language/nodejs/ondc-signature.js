/**
 * ONDC Ed25519 Signature Generator - Node.js Implementation
 * 
 * Implements the ONDC protocol signature scheme for V3 API authentication.
 */

import * as ed25519 from '@noble/ed25519';
import blake2b from 'blake2b';
import { createHash } from 'crypto';

// Set SHA-512 for ed25519 (required by @noble/ed25519 v2+)
ed25519.etc.sha512Sync = (...messages) => {
    const hash = createHash('sha512');
    for (const message of messages) hash.update(message);
    return Uint8Array.from(hash.digest());
};

class ONDCSignature {
    /**
     * Initialize ONDC signature generator.
     *
     * @param {string} subscriberId - Unique subscriber ID
     * @param {string} uniqueKeyId - Unique key identifier
     * @param {Buffer} privateKeySeed - 32-byte private key seed
     */
    constructor(subscriberId, uniqueKeyId, privateKeySeed) {
        this.subscriberId = subscriberId;
        this.uniqueKeyId = uniqueKeyId;
        
        if (!Buffer.isBuffer(privateKeySeed) || privateKeySeed.length !== 32) {
            throw new Error(`privateKeySeed must be exactly 32 bytes, got ${privateKeySeed.length}`);
        }
        
        this.privateKey = privateKeySeed;
        this.publicKey = ed25519.getPublicKey(this.privateKey);
        this.publicKeyB64 = this._getPublicKeyB64();
    }
    
    /**
     * Get DER/SPKI-encoded public key (base64).
     */
    _getPublicKeyB64() {
        // SPKI/DER header for Ed25519 public key
        const spkiHeader = Buffer.from([
            0x30, 0x2a,  // SEQUENCE, 42 bytes
            0x30, 0x05,  // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2b, 0x65, 0x70,  // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00  // BIT STRING, 33 bytes (including 0x00 padding)
        ]);
        
        const spkiEncoded = Buffer.concat([spkiHeader, Buffer.from(this.publicKey)]);
        return spkiEncoded.toString('base64');
    }
    
    /**
     * Create BLAKE2b-512 digest of request body.
     */
    _createDigest(body) {
        let bodyBytes;
        
        if (body === null || body === undefined || body === '') {
            bodyBytes = Buffer.from('');
        } else if (Buffer.isBuffer(body)) {
            bodyBytes = body;
        } else if (typeof body === 'string') {
            bodyBytes = Buffer.from(body, 'utf8');
        } else if (typeof body === 'object') {
            // Sort object keys recursively for consistency
            const sortedBody = this._sortObjectKeys(body);
            // Serialize with specific formatting (matches Python's json.dumps with sort_keys=True)
            // Use precise regex to only replace JSON structure separators, not colons/commas in values
            const json = JSON.stringify(sortedBody, null, 0)
                .replace(/":/g, '": ')  // Replace key-value separator only
                .replace(/,"/g, ', "')  // Replace element separator before string
                .replace(/},{/g, '}, {'); // Replace array element separator
            bodyBytes = Buffer.from(json, 'utf8');
        } else {
            throw new Error('Body must be null, string, Buffer, or object');
        }
        
        // Generate BLAKE2b-512 hash
        const hash = blake2b(64).update(bodyBytes).digest();
        return Buffer.from(hash).toString('base64');
    }
    
    /**
     * Create the signing string according to ONDC spec.
     */
    _createSigningString(created, expires, digest) {
        return `(created): ${created}\n(expires): ${expires}\ndigest: BLAKE-512=${digest}`;
    }
    
    /**
     * Sign the signing string with Ed25519 private key.
     */
    async _signString(signingString) {
        const message = Buffer.from(signingString, 'utf8');
        const signature = await ed25519.sign(message, this.privateKey);
        return Buffer.from(signature).toString('base64');
    }
    
    /**
     * Generate complete Signature authorization header.
     *
     * @param {*} body - Request body (can be null, string, Buffer, or object)
     * @param {number} created - Unix timestamp when signature was created (null for current time)
     * @param {number} expires - Unix timestamp when signature expires (null for created + 300)
     * @returns {Promise<string>} Authorization header string
     */
    async generateSignatureHeader(body, created = null, expires = null) {
        // Generate timestamps
        if (created === null) {
            created = Math.floor(Date.now() / 1000);
        }
        if (expires === null) {
            // 60-second validity window (ONDC recommended: 30-60 seconds)
            expires = created + 60;
        }
        
        // Create digest
        const digest = this._createDigest(body);
        
        // Create signing string
        const signingString = this._createSigningString(created, expires, digest);
        
        // Generate signature
        const signature = await this._signString(signingString);
        
        // Construct Signature header
        const keyId = `${this.subscriberId}|${this.uniqueKeyId}|ed25519`;
        
        return `Signature keyId="${keyId}",algorithm="ed25519",created="${created}",expires="${expires}",headers="(created) (expires) digest",signature="${signature}"`;
    }
    
    /**
     * Generate Digest header.
     */
    generateDigestHeader(body) {
        return `BLAKE-512=${this._createDigest(body)}`;
    }
    
    /**
     * Get public key (base64).
     */
    getPublicKey() {
        return this.publicKeyB64;
    }
    
    /**
     * Serialize body to JSON string matching the format used in digest calculation.
     * Use this when sending HTTP requests to ensure digest matches.
     * 
     * @param {*} body - Request body
     * @returns {string} Serialized JSON string
     */
    serializeBody(body) {
        if (body === null || body === undefined || body === '') {
            return '';
        } else if (typeof body === 'string') {
            return body;
        } else if (typeof body === 'object') {
            const sortedBody = this._sortObjectKeys(body);
            const json = JSON.stringify(sortedBody, null, 0)
                .replace(/":/g, '": ')  // Replace key-value separator only
                .replace(/,"/g, ', "')  // Replace element separator before string
                .replace(/},{/g, '}, {'); // Replace array element separator
            return json;
        }
        throw new Error('Body must be null, string, or object');
    }
    
    /**
     * Helper: Recursively sort object keys alphabetically for consistency.
     */
    _sortObjectKeys(obj) {
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
            return obj;
        }
        
        const sorted = {};
        Object.keys(obj).sort().forEach(key => {
            sorted[key] = this._sortObjectKeys(obj[key]);
        });
        return sorted;
    }
}

export default ONDCSignature;
