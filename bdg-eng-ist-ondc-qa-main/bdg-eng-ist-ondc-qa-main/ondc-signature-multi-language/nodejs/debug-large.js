const large_payload = {
    subscriber_id: "large-test.ondc.org",
    data: {
        field1: "value1",
        field2: "value2",
        field3: "value3",
        nested: {
            deep1: {
                deep2: {
                    deep3: {
                        value: "deeply nested value"
                    }
                }
            }
        },
        array: [
            {id: 1, name: "item1"},
            {id: 2, name: "item2"},
            {id: 3, name: "item3"},
            {id: 4, name: "item4"},
            {id: 5, name: "item5"}
        ]
    }
};

function sortObjectKeys(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    
    if (Array.isArray(obj)) {
        return obj.map(item => sortObjectKeys(item));
    }
    
    const sorted = {};
    Object.keys(obj).sort().forEach(key => {
        sorted[key] = sortObjectKeys(obj[key]);
    });
    return sorted;
}

const sortedBody = sortObjectKeys(large_payload);
const json = JSON.stringify(sortedBody)
    .replace(/":/g, '": ')  // Replace key-value separator only
    .replace(/,"/g, ', "')  // Replace element separator before string
    .replace(/},{/g, '}, {'); // Replace array element separator

console.log("=== Node.js JSON ===");
console.log(json);
console.log(`\nLength: ${json.length}`);
console.log(`\nFirst 200 chars:`);
console.log(json.substring(0, 200));
