#!/bin/bash

##############################################################################
# ONDC Gateway Testing - Quick Start Script
##############################################################################
# This script provides quick access to common test scenarios
##############################################################################

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          ONDC Gateway API Testing - Quick Start               ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_menu() {
    echo -e "${GREEN}Available Test Scenarios:${NC}"
    echo ""
    echo "  1. Search API - Functional Tests (5 iterations)"
    echo "  1a. Search API - Domains Test TC-002 Only (5 iterations)"
    echo "  1b. Search API - Large Payload TC-004 Only (5 iterations)"
    echo "  1c. Search API - Large Payload TC-004 Performance (50 users, 2 min)"
    echo "  2. Search API - Light Performance (10 users, 1 min)"
    echo "  3. Search API - Medium Performance (50 users, 3 min)"
    echo "  4. Search API - Heavy Performance (100 users, 5 min)"
    echo "  5. Search API - Stress Test (200 users, 2 min)"
    echo ""
    echo "  6. Lookup API - Functional Tests (5 iterations)"
    echo "  7. Lookup API - Performance Test (50 users, 3 min)"
    echo ""
    echo "  8. Full Test Suite (All tests)"
    echo "  9. Custom Test (Enter parameters)"
    echo ""
    echo "  0. Exit"
    echo ""
}

run_test() {
    local test_case=$1
    local env=$2
    local extra_args=$3
    
    timestamp=$(date +%Y%m%d_%H%M%S)
    report_dir="results"
    mkdir -p "$report_dir"
    
    echo -e "${BLUE}Running test: $test_case${NC}"
    echo "Environment: $env"
    echo "Report will be saved to: $report_dir/"
    echo ""
    
    python driver.py "$test_case" \
        --environment "$env" \
        --html "$report_dir/${test_case}_${timestamp}.html" \
        $extra_args
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Test completed successfully!${NC}"
        echo -e "Report: ${report_dir}/${test_case}_${timestamp}.html"
    else
        echo -e "${YELLOW}⚠ Test completed with warnings${NC}"
    fi
    echo ""
}

# Main menu
clear
print_header

# Check prerequisites
if ! command -v python &> /dev/null; then
    echo "Error: Python not found. Please install Python 3.8+"
    exit 1
fi

if ! python -c "import common_test_foundation" 2>/dev/null; then
    echo -e "${YELLOW}Warning: common-test-foundation not installed${NC}"
    echo "Installing dependencies..."
    pip install -r requirements.txt
    echo ""
fi

while true; do
    print_menu
    read -p "Select option (0-9, 1a-1c): " choice
    
    case $choice in
        1)
            run_test "ondc_gateway_search_functional" "ondcGatewaySearch" "--iterations 5"
            ;;
        1a|1A)
            run_test "ondc_gateway_search_domains_functional" "ondcGatewaySearch" "--iterations 5"
            ;;
        1b|1B)
            run_test "ondc_gateway_search_large_payload" "ondcGatewaySearch" "--iterations 5"
            ;;
        1c|1C)
            run_test "ondc_gateway_search_large_payload" "ondcGatewaySearch" "--users 50 --spawn-rate 10 --run-time 120"
            ;;
        2)
            run_test "ondc_gateway_search_performance_light" "ondcGatewaySearch" "--users 10 --spawn-rate 2 --run-time 60"
            ;;
        3)
            run_test "ondc_gateway_search_performance_medium" "ondcGatewaySearch" "--users 50 --spawn-rate 10 --run-time 180"
            ;;
        4)
            run_test "ondc_gateway_search_performance_heavy" "ondcGatewaySearch" "--users 100 --spawn-rate 20 --run-time 300"
            ;;
        5)
            run_test "ondc_gateway_search_stress" "ondcGatewaySearch" "--users 200 --spawn-rate 50 --run-time 120"
            ;;
        6)
            run_test "ondc_gateway_lookup_functional" "ondcGatewaySearch" "--iterations 5"
            ;;
        7)
            run_test "ondc_gateway_lookup_performance" "ondcGatewaySearch" "--users 50 --spawn-rate 10 --run-time 180"
            ;;
        8)
            echo -e "${BLUE}Running full test suite...${NC}"
            run_test "ondc_gateway_search_functional" "ondcGatewaySearch" "--iterations 3"
            run_test "ondc_gateway_lookup_functional" "ondcGatewaySearch" "--iterations 3"
            run_test "ondc_gateway_search_performance_light" "ondcGatewaySearch" "--users 10 --spawn-rate 2 --run-time 60"
            run_test "ondc_gateway_lookup_performance" "ondcGatewaySearch" "--users 20 --spawn-rate 5 --run-time 60"
            echo -e "${GREEN}✓ Full test suite completed!${NC}"
            ;;
        9)
            echo ""
            read -p "Test case name: " test_case
            read -p "Environment (default: ondcGatewaySearch): " env
            env=${env:-ondcGatewaySearch}
            read -p "Users (or blank for iterations mode): " users
            
            if [ -z "$users" ]; then
                read -p "Iterations: " iterations
                run_test "$test_case" "$env" "--iterations $iterations"
            else
                read -p "Spawn rate: " spawn_rate
                read -p "Run time (seconds): " run_time
                run_test "$test_case" "$env" "--users $users --spawn-rate $spawn_rate --run-time $run_time"
            fi
            ;;
        0)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo -e "${YELLOW}Invalid option. Please select 0-9, 1a, or 1b${NC}"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
    clear
    print_header
done
