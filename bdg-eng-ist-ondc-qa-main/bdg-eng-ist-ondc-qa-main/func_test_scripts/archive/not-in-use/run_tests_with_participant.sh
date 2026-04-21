#!/bin/bash
# Run tests with automatic participant registration
# Usage: ./run_tests_with_participant.sh [test_name] [iterations]
#
# Examples:
#   ./run_tests_with_participant.sh ondc_reg_lookup_negative 3
#   ./run_tests_with_participant.sh ondc_reg_lookup_functional 1

set -e  # Exit on error

TEST_NAME="${1:-ondc_reg_lookup_negative}"
ITERATIONS="${2:-2}"
USERS="${3:-1}"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ONDC Registry Test Runner with Auto-Registration         ║"
echo "╔════════════════════════════════════════════════════════════╗"
echo ""
echo "Test: $TEST_NAME"
echo "Iterations: $ITERATIONS"
echo "Users: $USERS"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WORKSPACE_DIR="$(dirname "$SCRIPT_DIR")"

cd "$WORKSPACE_DIR"

# Step 1: Ensure participant is registered
echo "───────────────────────────────────────────────────────────"
echo "Step 1: Checking/Registering Test Participant"
echo "───────────────────────────────────────────────────────────"

if ! python3 func_test_scripts/ensure_test_participant.py; then
    echo ""
    echo "❌ Failed to ensure participant registration"
    echo "   Tests may fail with 'Subscriber not found' error"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 2: Run the tests
echo ""
echo "───────────────────────────────────────────────────────────"
echo "Step 2: Running Tests"
echo "───────────────────────────────────────────────────────────"
echo ""

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HTML_REPORT="results/registry/${TEST_NAME}-${TIMESTAMP}.html"

python driver.py \
    --test "$TEST_NAME" \
    --environment ondcRegistry \
    --iterations "$ITERATIONS" \
    -u "$USERS" \
    --autostart \
    --autoquit 1 \
    --html "$HTML_REPORT"

TEST_EXIT_CODE=$?

echo ""
echo "───────────────────────────────────────────────────────────"
echo "Test Execution Complete"
echo "───────────────────────────────────────────────────────────"

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Tests completed successfully"
else
    echo "⚠️  Tests completed with failures (exit code: $TEST_EXIT_CODE)"
fi

echo ""
echo "📊 View HTML report: $HTML_REPORT"
echo ""

exit $TEST_EXIT_CODE
