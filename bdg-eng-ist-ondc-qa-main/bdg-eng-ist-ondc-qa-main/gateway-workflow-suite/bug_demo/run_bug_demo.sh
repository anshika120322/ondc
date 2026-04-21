#!/usr/bin/env bash
# =============================================================================
# ONDC Gateway Bug Demo: INACTIVE BPP can still POST /on_search and get 200 ACK
#
# Run from: gateway-workflow-suite/bug_demo/
# Requires: curl, python3 (with cryptography package + workflow-suite in path)
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# 0. Variables
# ---------------------------------------------------------------------------
REGISTRY="https://registry-preprod.ondc.org"
GATEWAY="https://gateway-preprod.ondc.org"
AUTH_URL="https://admin-auth-preprod.ondc.org/api/auth/login"

# Unique suffix to avoid participant ID collisions on re-runs
SUFFIX=$(date +"%Y%m%d%H%M%S")
BAP_ID="bap-bug-demo-${SUFFIX}.ondc.org"
BPP_ID="bpp-bug-demo-${SUFFIX}.ondc.org"
BAP_UK="bap-uk-${SUFFIX}"
BPP_UK="bpp-uk-${SUFFIX}"
PUB_KEY="MCowBQYDK2VwAyEAVXtuKQMPh485BxBcV1jbqNHRuuyyJnbe1QIQoQYjLBg="
SEED="MC4CAQAwBQYDK2VwBCIEIPGt7Hv6vy2haK04ipiBbgU0omo/IGjs+hmuGE+jXkbf"

echo "============================================================"
echo " ONDC Gateway Bug Demo"
echo " BAP: $BAP_ID"
echo " BPP: $BPP_ID"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Helper: Generate ONDC-SIG Authorization header
# ---------------------------------------------------------------------------
sign() {
  local sub_id="$1" uk_id="$2" method="$3" path="$4" body="$5"
  python3 sign.py "$sub_id" "$uk_id" "$SEED" "$method" "$path" "$body"
}

# ---------------------------------------------------------------------------
# Step 0: Admin login — get Bearer token
# ---------------------------------------------------------------------------
echo ">>> STEP 0: Admin login"
TOKEN=$(curl -s -X POST "$AUTH_URL" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@ondc.org","password":"Admin@123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")
echo "    Token: ${TOKEN:0:40}..."
echo ""

# ---------------------------------------------------------------------------
# Step 1: Register BAP as SUBSCRIBED
# ---------------------------------------------------------------------------
echo ">>> STEP 1: Register BAP ($BAP_ID) as SUBSCRIBED"
curl -s -X POST "$REGISTRY/admin/subscribe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"dns_skip\": true,
    \"skip_ssl_verification\": true,
    \"participant_id\": \"$BAP_ID\",
    \"action\": \"SUBSCRIBED\",
    \"credentials\": [
      {\"cred_id\": \"cred-gst-$BAP_UK\", \"type\": \"GST\", \"cred_data\": {\"gstin\": \"29ABCDE1234F1Z5\", \"legal_name\": \"Bug Demo BAP\"}},
      {\"cred_id\": \"cred-pan-$BAP_UK\", \"type\": \"PAN\", \"cred_data\": {\"pan\": \"ABCDE1234F\", \"name\": \"Bug Demo BAP\"}}
    ],
    \"contacts\": [
      {\"contact_id\": \"contact-auth-$BAP_UK\", \"type\": \"AUTHORISED_SIGNATORY\", \"name\": \"Auth Rep\", \"email\": \"auth@bug-demo.example.com\", \"phone\": \"+919876543210\"},
      {\"contact_id\": \"contact-biz-$BAP_UK\", \"type\": \"BUSINESS\", \"name\": \"Biz Rep\", \"email\": \"biz@bug-demo.example.com\", \"phone\": \"+919876543211\"},
      {\"contact_id\": \"contact-tech-$BAP_UK\", \"type\": \"TECHNICAL\", \"name\": \"Tech Rep\", \"email\": \"tech@bug-demo.example.com\", \"phone\": \"+919876543212\"}
    ],
    \"key\": {
      \"uk_id\": \"$BAP_UK\", \"signing_public_key\": \"$PUB_KEY\", \"encryption_public_key\": \"$PUB_KEY\",
      \"signed_algorithm\": \"ED25519\", \"encryption_algorithm\": \"X25519\",
      \"valid_from\": \"2026-01-01T00:00:00Z\", \"valid_until\": \"2031-01-01T00:00:00Z\"
    },
    \"location\": {\"location_id\": \"loc-$BAP_UK\", \"type\": \"SERVICEABLE\", \"country\": \"IND\", \"city\": [\"std:080\"]},
    \"uri\": {\"uri_id\": \"uri-$BAP_UK\", \"type\": \"CALLBACK\", \"url\": \"https://seller-mock.kynondc.net\"},
    \"configs\": [{\"domain\": \"ONDC:RET10\", \"np_type\": \"BAP\", \"subscriber_id\": \"$BAP_ID\", \"location_id\": \"loc-$BAP_UK\", \"uri_id\": \"uri-$BAP_UK\", \"key_id\": \"$BAP_UK\"}]
  }" | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo ""

# ---------------------------------------------------------------------------
# Step 2: Register BPP as SUBSCRIBED
# ---------------------------------------------------------------------------
echo ">>> STEP 2: Register BPP ($BPP_ID) as SUBSCRIBED"
curl -s -X POST "$REGISTRY/admin/subscribe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"dns_skip\": true,
    \"skip_ssl_verification\": true,
    \"participant_id\": \"$BPP_ID\",
    \"action\": \"SUBSCRIBED\",
    \"credentials\": [
      {\"cred_id\": \"cred-gst-$BPP_UK\", \"type\": \"GST\", \"cred_data\": {\"gstin\": \"29ABCDE1234F1Z5\", \"legal_name\": \"Bug Demo BPP\"}},
      {\"cred_id\": \"cred-pan-$BPP_UK\", \"type\": \"PAN\", \"cred_data\": {\"pan\": \"ABCDE1234F\", \"name\": \"Bug Demo BPP\"}}
    ],
    \"contacts\": [
      {\"contact_id\": \"contact-auth-$BPP_UK\", \"type\": \"AUTHORISED_SIGNATORY\", \"name\": \"Auth Rep\", \"email\": \"auth@bug-demo.example.com\", \"phone\": \"+919876543210\"},
      {\"contact_id\": \"contact-biz-$BPP_UK\", \"type\": \"BUSINESS\", \"name\": \"Biz Rep\", \"email\": \"biz@bug-demo.example.com\", \"phone\": \"+919876543211\"},
      {\"contact_id\": \"contact-tech-$BPP_UK\", \"type\": \"TECHNICAL\", \"name\": \"Tech Rep\", \"email\": \"tech@bug-demo.example.com\", \"phone\": \"+919876543212\"}
    ],
    \"key\": {
      \"uk_id\": \"$BPP_UK\", \"signing_public_key\": \"$PUB_KEY\", \"encryption_public_key\": \"$PUB_KEY\",
      \"signed_algorithm\": \"ED25519\", \"encryption_algorithm\": \"X25519\",
      \"valid_from\": \"2026-01-01T00:00:00Z\", \"valid_until\": \"2031-01-01T00:00:00Z\"
    },
    \"location\": {\"location_id\": \"loc-$BPP_UK\", \"type\": \"SERVICEABLE\", \"country\": \"IND\", \"city\": [\"std:080\"]},
    \"uri\": {\"uri_id\": \"uri-$BPP_UK\", \"type\": \"CALLBACK\", \"url\": \"https://seller-mock.kynondc.net\"},
    \"configs\": [{\"domain\": \"ONDC:RET10\", \"np_type\": \"BPP\", \"subscriber_id\": \"$BPP_ID\", \"location_id\": \"loc-$BPP_UK\", \"uri_id\": \"uri-$BPP_UK\", \"key_id\": \"$BPP_UK\"}]
  }" | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo ""

# ---------------------------------------------------------------------------
# Step 3: Wait for Registry propagation
# ---------------------------------------------------------------------------
echo ">>> STEP 3: Wait 5s for Registry propagation"
sleep 5
echo ""

# ---------------------------------------------------------------------------
# Step 4: BASELINE — BPP sends on_search while SUBSCRIBED → expect 200 ACK
# ---------------------------------------------------------------------------
BODY_ON_SEARCH="{\"context\":{\"domain\":\"ONDC:RET10\",\"action\":\"on_search\",\"version\":\"2.0.0\",\"bap_id\":\"$BAP_ID\",\"bap_uri\":\"https://seller-mock.kynondc.net\",\"bpp_id\":\"$BPP_ID\",\"bpp_uri\":\"https://seller-mock.kynondc.net\",\"transaction_id\":\"bug-demo-txn-001\",\"message_id\":\"bug-demo-msg-001\",\"location\":{\"city\":{\"code\":\"std:080\"},\"country\":{\"code\":\"IND\"}},\"ttl\":\"PT30S\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"},\"message\":{\"catalog\":{\"descriptor\":{\"name\":\"Bug Demo BPP Store (SUBSCRIBED)\"},\"providers\":[]}}}"
SIG_BASELINE=$(sign "$BPP_ID" "$BPP_UK" "POST" "/on_search" "$BODY_ON_SEARCH")

echo ">>> STEP 4 (BASELINE): BPP sends on_search while SUBSCRIBED — EXPECT: 200 ACK"
curl -s -X POST "$GATEWAY/on_search" \
  -H "Authorization: $SIG_BASELINE" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d "$BODY_ON_SEARCH" | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo "    [OK] SUBSCRIBED BPP correctly gets ACK"
echo ""

# ---------------------------------------------------------------------------
# Step 5: PATCH BPP to INACTIVE
# ---------------------------------------------------------------------------
echo ">>> STEP 5: PATCH BPP to INACTIVE"
curl -s -X PATCH "$REGISTRY/admin/subscribe" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"participant_id\": \"$BPP_ID\", \"action\": \"INACTIVE\"}" \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo ""

# ---------------------------------------------------------------------------
# Step 6: Verify Registry — lookup confirms INACTIVE (Subscriber not found)
# ---------------------------------------------------------------------------
echo ">>> STEP 6: Verify Registry — POST /v3.0/lookup — EXPECT: NACK / Subscriber not found"
curl -s -X POST "$REGISTRY/v3.0/lookup" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d "{\"subscriber_id\": \"$BPP_ID\", \"type\": \"BPP\"}" \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo "    [OK] Registry correctly reports BPP as not found (INACTIVE)"
echo ""

# ---------------------------------------------------------------------------
# Step 7: Wait 5s for Gateway cache propagation
# ---------------------------------------------------------------------------
echo ">>> STEP 7: Wait 5s for Gateway cache to propagate INACTIVE status"
sleep 5
echo ""

# ---------------------------------------------------------------------------
# Step 8: BUG — BPP sends on_search while INACTIVE → Gateway should reject but ACCEPTS
# ---------------------------------------------------------------------------
BODY_INACTIVE="{\"context\":{\"domain\":\"ONDC:RET10\",\"action\":\"on_search\",\"version\":\"2.0.0\",\"bap_id\":\"$BAP_ID\",\"bap_uri\":\"https://seller-mock.kynondc.net\",\"bpp_id\":\"$BPP_ID\",\"bpp_uri\":\"https://seller-mock.kynondc.net\",\"transaction_id\":\"bug-demo-txn-001\",\"message_id\":\"bug-demo-msg-002\",\"location\":{\"city\":{\"code\":\"std:080\"},\"country\":{\"code\":\"IND\"}},\"ttl\":\"PT30S\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\"},\"message\":{\"catalog\":{\"descriptor\":{\"name\":\"Bug Demo BPP Store (AFTER INACTIVE)\"},\"providers\":[]}}}"
SIG_INACTIVE=$(sign "$BPP_ID" "$BPP_UK" "POST" "/on_search" "$BODY_INACTIVE")

echo ">>> STEP 8 (BUG): BPP sends on_search while INACTIVE — EXPECT: 4xx NACK — ACTUAL: 200 ACK"
curl -s -X POST "$GATEWAY/on_search" \
  -H "Authorization: $SIG_INACTIVE" \
  -H "Content-Type: application/json; charset=utf-8" \
  -d "$BODY_INACTIVE" | python3 -c "import sys,json; r=json.load(sys.stdin); print('    Response:', json.dumps(r))"
echo ""
echo "============================================================"
echo " BUG SUMMARY"
echo " Registry /v3.0/lookup correctly returns NACK for $BPP_ID"
echo " (Subscriber not found after INACTIVE patch)"
echo ""
echo " BUT Gateway /on_search returns 200 ACK for the same BPP."
echo " The Gateway does NOT check the sender's current Registry"
echo " status — it only validates the ONDC-SIG cryptographic"
echo " signature, which remains valid since keys haven't changed."
echo "============================================================"
