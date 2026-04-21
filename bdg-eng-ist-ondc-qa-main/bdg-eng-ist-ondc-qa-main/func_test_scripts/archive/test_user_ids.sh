#!/bin/bash
# Test different userId values to find valid one

echo "Testing different userId values..."
echo ""

for user_id in "admin" "1" "admin@kynondc.net" "00000000-0000-0000-0000-000000000001" "admin123"
do
    echo "==============================================="
    echo "Testing userId: $user_id"
    echo "==============================================="
    
    python func_test_scripts/mock_jwt_generator.py \
        --email admin@kynondc.net \
        --user-id "$user_id" \
        --role admin \
        --hours 1 \
        --save-config > /dev/null 2>&1
    
    # Quick test: try to GET /admin/policy
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $(grep 'admin_token:' resources/registry/subscribe/test_subscribe_functional.yml | awk '{print $2}')" \
        -H "Content-Type: application/json" \
        http://34.14.152.92/admin/policy?policy_id=test)
    
    echo "GET /admin/policy response: $response"
    
    # Try POST test
    if [ "$response" = "200" ]; then
        echo "✅ GET works! Now trying POST..."
        
        token=$(grep 'admin_token:' resources/registry/subscribe/test_subscribe_functional.yml | awk '{print $2}')
        
        post_response=$(curl -s -X POST http://34.14.152.92/admin/policy \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d '{
                "type": "NETWORK",
                "participant_id": "test.participant.ondc",
                "routing_policy": {
                    "action": "allow",
                    "priority": 1
                }
            }')
        
        echo "POST response: $post_response"
    fi
    
    echo ""
done
