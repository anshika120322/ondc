#!/bin/bash
# Script to run ONDC Policy Management Tests

echo "=========================================="
echo "ONDC Policy Management Tests"
echo "=========================================="
echo ""

# Activate virtual environment if available
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Check if driver.py exists
if [ ! -f "driver.py" ]; then
    echo "ERROR: driver.py not found. Please run from project root."
    exit 1
fi

# Run policy tests
echo "Running Policy Management Tests..."
echo ""

python driver.py \
    --test ondc_policy_functional \
    --environment ondcRegistry \
    --users 1 \
    --iterations 1 \
    --html results/registry/policy_test_report_$(date +%Y%m%d_%H%M%S).html

echo ""
echo "=========================================="
echo "Test execution completed!"
echo "=========================================="
