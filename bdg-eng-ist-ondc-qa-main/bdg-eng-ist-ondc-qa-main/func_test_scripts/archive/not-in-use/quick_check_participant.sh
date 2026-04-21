#!/bin/bash
# Quick check if participant is visible in lookup server

PARTICIPANT="test-v3-feb2026-fresh.participant.ondc"
LOOKUP_SERVER="http://35.200.190.239:8080"

echo ""
echo "🔍 Quick Participant Check"
echo "================================"
echo "Time: $(date '+%H:%M:%S')"
echo "Participant: $PARTICIPANT"
echo ""

RESULT=$(curl -s "$LOOKUP_SERVER/lookup" \
    -H "Content-Type: application/json" \
    -d "{\"subscriber_id\":\"$PARTICIPANT\",\"country\":\"IND\"}" \
    2>&1 | grep -i "$PARTICIPANT" || echo "")

if [ -n "$RESULT" ]; then
    echo "✅ FOUND! Participant is now visible in lookup server!"
    echo ""
    echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"
    echo ""
    echo "🎉 You can now run negative tests!"
    echo "   python driver.py --test ondc_reg_lookup_negative --iterations 2"
    echo ""
else
    echo "❌ Not yet visible in lookup server"
    echo "⏳ Continue monitoring or check again later"
    echo ""
fi
