#!/bin/bash
#===============================================================================
# ONDC QA Framework - macOS/Linux Setup Script
#===============================================================================
# This script helps new users set up the test environment on macOS/Linux
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}========================================================================"
echo -e "  ONDC QA Framework - macOS/Linux Setup"
echo -e "========================================================================${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: Python3 is not installed${NC}"
    echo "Please install Python 3.12 or higher"
    exit 1
fi

echo -e "${GREEN}[1/5]${NC} Python version check..."
python3 --version

# Create virtual environment
if [ ! -d "venv" ]; then
    echo ""
    echo -e "${GREEN}[2/5]${NC} Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo ""
    echo -e "${GREEN}[2/5]${NC} Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo -e "${GREEN}[3/5]${NC} Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo ""
echo -e "${GREEN}[4/5]${NC} Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo ""
echo -e "${GREEN}[5/5]${NC} Installing dependencies..."
pip install -r requirements.txt

# Verify setup
echo ""
echo -e "${BLUE}========================================================================"
echo -e "  Verifying Installation..."
echo -e "========================================================================${NC}"
python func_test_scripts/verify_setup.py

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================================================"
    echo -e "  SUCCESS! Environment is ready for testing"
    echo -e "========================================================================${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Configure your environment in resources/environments.yml"
    echo "  2. Run a test:"
    echo "     python driver.py --test-case ondc_gateway_search_functional --env qa"
    echo ""
else
    echo ""
    echo -e "${YELLOW}WARNING: Some checks failed. Please review the output above.${NC}"
    echo "See SETUP.md for troubleshooting help."
    exit 1
fi
