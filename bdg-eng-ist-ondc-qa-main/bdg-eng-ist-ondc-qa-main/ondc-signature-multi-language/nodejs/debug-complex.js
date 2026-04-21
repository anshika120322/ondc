const complex_json = {
    subscriber_id: "test.ondc.org",
    unique_key_id: "test-key-123",
    key_pair: {
        signing_public_key: "MCowBQYDK2VwAyEA...",
        encryption_public_key: "MCowBQYDK2VuAyEA...",
        valid_from: "2024-01-01T00:00:00Z",
        valid_until: "2025-12-31T23:59:59Z"
    },
    country: "IND",
    city: "std:080",
    domain: "ONDC:RET10",
    subscriber_url: "https://test.ondc.org/callback"
};

function sortObjectKeys(obj) {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
        return obj;
    }
    
    const sorted = {};
    Object.keys(obj).sort().forEach(key => {
        sorted[key] = sortObjectKeys(obj[key]);
    });
    return sorted;
}

const sortedBody = sortObjectKeys(complex_json);
const json = JSON.stringify(sortedBody)
    .replace(/":/g, '": ')  // Replace key-value separator only
    .replace(/,"/g, ', "'); // Replace element separator only

console.log("=== Node.js JSON (sorted) ===");
console.log(json);
console.log(`\nLength: ${json.length}`);
console.log(`Bytes (first 100): ${Buffer.from(json, 'utf8').toString('hex').substring(0, 200)}`);
