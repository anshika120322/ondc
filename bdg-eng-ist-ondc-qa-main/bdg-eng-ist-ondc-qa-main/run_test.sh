#!/bin/bash
# Convenience wrapper to run tests with custom HTML/JSON reports
# Usage: ./run_test.sh <test_name> <environment> [additional_args]

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./run_test.sh <test_name> <environment> [additional_args]"
    echo ""
    echo "Examples:"
    echo "  ./run_test.sh ondc_reg_v3_lookup_functional ondcRegistry"
    echo "  ./run_test.sh ondc_reg_v3_lookup_negative ondcRegistry --run-time 60s"
    echo "  ./run_test.sh ondc_reg_subscribe_functional ondcEnv --users 1 --run-time 30s"
    echo ""
    echo "Available tests (see config.yml):"
    echo "  - ondc_reg_v3_lookup_functional"
    echo "  - ondc_reg_v3_lookup_negative"
    echo "  - ondc_reg_v3_lookup_boundary"
    echo "  - ondc_reg_subscribe_functional"
    echo "  - ondc_reg_v3_comprehensive"
    echo ""
    exit 1
fi

TEST_NAME=$1
ENVIRONMENT=$2
shift 2  # Remove first two args, rest will be passed as additional args

# Find the test case module from config.yml
TEST_MODULE=$(grep -A5 "^  ${TEST_NAME}:" config.yml | grep "test_case_module:" | head -1 | awk '{print $2}' | sed 's/tests\.//' | tr '.' '/')

if [ -z "$TEST_MODULE" ]; then
    echo "Error: Test '$TEST_NAME' not found in config.yml"
    exit 1
fi

echo "Running test: $TEST_NAME"
echo "Environment: $ENVIRONMENT"
echo "Module: tests/$TEST_MODULE.py"
echo ""

# Run the test with custom reporting
python run_test_with_reports.py \
    -f "tests/$TEST_MODULE.py" \
    --test "$TEST_NAME" \
    --env "$ENVIRONMENT" \
    --headless \
    --users 1 \
    --spawn-rate 1 \
    --run-time 30s \
    --skip-locust-html \
    "$@"
