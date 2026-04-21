#!/bin/bash

# Run All Lookup Tests (V1, V2, V3) in UAT Environment
# Updated to use http://35.200.145.160:8080
# Uses SequentialTaskSet: Each test case runs exactly once per iteration
# Date: March 11, 2026

set -e  # Exit on error

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="results/registry/lookup"

echo "=================================================="
echo "ONDC Registry Lookup Tests - UAT Environment"
echo "Target: http://35.200.145.160:8080"
echo "Mode: Sequential execution (each test runs once)"
echo "Started: $(date)"
echo "=================================================="

# Create results directory if it doesn't exist
mkdir -p "$RESULTS_DIR"

# ========================================
# V1 LOOKUP TESTS (47 total test cases)
# ========================================
echo -e "\n[1/13] Running V1 Functional Tests (12 test cases)..."
python driver.py --test ondc_reg_v1_lookup_functional \
  --environment ondcRegistryV1Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v1_functional_uat_${TIMESTAMP}.html"

echo -e "\n[2/13] Running V1 Negative Tests (20 test cases)..."
python driver.py --test ondc_reg_v1_lookup_negative \
  --environment ondcRegistryV1Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v1_negative_uat_${TIMESTAMP}.html"

echo -e "\n[3/13] Running V1 Filter Combination Tests (13 test cases)..."
python driver.py --test ondc_reg_v1_lookup_filter_combinations \
  --environment ondcRegistryV1Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v1_filter_combinations_uat_${TIMESTAMP}.html"

echo -e "\n[4/13] Running V1 Boundary Tests (12 test cases)..."
python driver.py --test ondc_reg_v1_lookup_boundary \
  --environment ondcRegistryV1Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v1_boundary_uat_${TIMESTAMP}.html"

# ========================================
# V2 LOOKUP TESTS (62 total test cases)
# ========================================
echo -e "\n[5/13] Running V2 Functional Tests (11 test cases)..."
python driver.py --test ondc_reg_v2_lookup_functional \
  --environment ondcRegistryV2Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v2_functional_uat_${TIMESTAMP}.html"

echo -e "\n[6/13] Running V2 Negative Tests (30 test cases)..."
python driver.py --test ondc_reg_v2_lookup_negative \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v2_negative_uat_${TIMESTAMP}.html"

echo -e "\n[7/13] Running V2 Filter Combination Tests (11 test cases)..."
python driver.py --test ondc_reg_v2_lookup_filter_combinations \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v2_filter_combinations_uat_${TIMESTAMP}.html"

echo -e "\n[8/13] Running V2 Boundary Tests (10 test cases)..."
python driver.py --test ondc_reg_v2_lookup_boundary \
  --environment ondcRegistryV2Lookup \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v2_boundary_uat_${TIMESTAMP}.html"

# ========================================
# V3 LOOKUP TESTS (72 total test cases)
# ========================================
echo -e "\n[9/13] Running V3 Functional Tests (11 test cases)..."
python driver.py --test ondc_reg_v3_lookup_functional \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v3_functional_uat_${TIMESTAMP}.html"

echo -e "\n[10/13] Running V3 Negative Tests (30 test cases)..."
python driver.py --test ondc_reg_v3_lookup_negative \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v3_negative_uat_${TIMESTAMP}.html"

echo -e "\n[11/13] Running V3 Boundary Tests (10 test cases)..."
python driver.py --test ondc_reg_v3_lookup_boundary \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v3_boundary_uat_${TIMESTAMP}.html"

echo -e "\n[12/13] Running V3 Filter Combination Tests (21 test cases)..."
python driver.py --test ondc_reg_v3_lookup_filter_combinations \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/v3_filter_combinations_uat_${TIMESTAMP}.html"

# ========================================
# VERSION COMPARISON TESTS
# ========================================
echo -e "\n[13/13] Running Version Comparison Tests..."
python driver.py --test ondc_reg_version_comparison \
  --environment ondcRegistry \
  --users 1 --iterations 1 \
  --autostart --autoquit 1 \
  --html "$RESULTS_DIR/version_comparison_uat_${TIMESTAMP}.html"

# ========================================
# SUMMARY
# ========================================
echo -e "\n=================================================="
echo "All Lookup Tests Completed!"
echo "Total Test Cases: 181 (V1: 47, V2: 62, V3: 72)"
echo "Each test case ran exactly once"
echo "Completed: $(date)"
echo "Results saved in: $RESULTS_DIR"
echo "=================================================="
echo -e "\nTest Results:"
ls -lh "$RESULTS_DIR"/*_uat_${TIMESTAMP}.html
