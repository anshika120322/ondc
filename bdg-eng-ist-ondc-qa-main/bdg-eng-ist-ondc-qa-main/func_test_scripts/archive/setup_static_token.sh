#!/bin/bash
# Quick Reference: Get Token and Run Tests

echo "=================================================="
echo "🔐 ONDC Policy Tests - Static Token Setup"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}📋 Step 1: Get JWT Token${NC}"
echo ""
echo "You need valid credentials to obtain a token."
echo ""
echo "Option A: Use the token fetcher script"
echo "  ${GREEN}python func_test_scripts/get_jwt_token.py --email YOUR_EMAIL --password YOUR_PASSWORD --save-config${NC}"
echo ""
echo "Option B: Use curl manually"
echo "  ${GREEN}curl -X POST https://authservice.kynondc.net/api/auth/login \\${NC}"
echo "  ${GREEN}    -H 'Content-Type: application/json' \\${NC}"
echo "  ${GREEN}    -d '{\"email\": \"YOUR_EMAIL\", \"password\": \"YOUR_PASSWORD\"}'${NC}"
echo ""
echo "Option C: Ask your team for a pre-generated token"
echo ""
echo "---------------------------------------------------"
echo ""

echo -e "${YELLOW}📝 Step 2: Configure Static Token${NC}"
echo ""
echo "Edit: resources/registry/subscribe/test_subscribe_functional.yml"
echo ""
echo "Set the admin_token field:"
echo "  ${GREEN}admin_token: \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"${NC}"
echo ""
echo "You can clear username/password when using a token:"
echo "  ${GREEN}admin_username: \"\"${NC}"
echo "  ${GREEN}admin_password: \"\"${NC}"
echo ""
echo "---------------------------------------------------"
echo ""

echo -e "${YELLOW}🚀 Step 3: Run Tests${NC}"
echo ""
echo "Run policy tests:"
echo "  ${GREEN}python driver.py --test ondc_policy_functional --environment ondcRegistry --users 1 --iterations 1 --autostart --autoquit 1${NC}"
echo ""
echo "Or use VS Code (F5) with the launch configuration"
echo ""
echo "---------------------------------------------------"
echo ""

echo -e "${YELLOW}✅ Expected Output${NC}"
echo ""
echo "When static token is configured, you should see:"
echo "  ${GREEN}[ON_START] Using static admin token (no login required)${NC}"
echo "  ${GREEN}[RegistryAuthClient] Using static token (no expiry check)${NC}"
echo ""
echo "Tests will skip login and use your token directly!"
echo ""
echo "---------------------------------------------------"
echo ""

echo -e "${YELLOW}📚 Documentation${NC}"
echo ""
echo "Full guides available:"
echo "  • STATIC_TOKEN_SETUP.md    - Complete setup guide"
echo "  • STATIC_TOKEN_EXAMPLE.md  - Quick examples"
echo "  • POLICY_TEST_FINDINGS.md  - Overall test setup"
echo ""
echo "---------------------------------------------------"
echo ""

echo -e "${YELLOW}🆘 Don't Have Credentials?${NC}"
echo ""
echo "Contact your team and request:"
echo "  1. Valid email/password for authservice.kynondc.net"
echo "  2. OR a pre-generated JWT token (valid for 24+ hours)"
echo "  3. With admin permissions for /admin/policy endpoints"
echo ""
echo "=================================================="
echo ""

# Example: If user provides credentials via args
if [ ! -z "$1" ] && [ ! -z "$2" ]; then
    echo -e "${GREEN}🔄 Attempting to get token with provided credentials...${NC}"
    echo ""
    python func_test_scripts/get_jwt_token.py --email "$1" --password "$2" --save-config
fi
