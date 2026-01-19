#!/bin/bash
# Test script for nginx update crash fixes
# This tests the cleanup_on_exit trap function and recovery logic

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

test_result() {
    local test_name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo -e "${GREEN}PASS${NC}: $test_name"
        ((PASSED++))
    else
        echo -e "${RED}FAIL${NC}: $test_name"
        ((FAILED++))
    fi
}

echo "============================================"
echo "Testing Nginx Update Crash Fixes"
echo "============================================"
echo ""

# Test 1: Check trap function has multiple PHP version fallbacks
echo "Test 1: Trap function has multiple PHP version fallback methods"
FALLBACK_COUNT=$(grep -c "Fallback" /home/user/irongate/irongate-install.sh)
[ "$FALLBACK_COUNT" -ge 3 ]
test_result "Trap has at least 3 PHP version fallback methods" $?

# Test 2: Check trap function has sleep between PHP-FPM and nginx restart
echo ""
echo "Test 2: Trap function has delay between PHP-FPM restart and nginx restart"
# Extract the cleanup_on_exit function and check for sleep after php-fpm restart
TRAP_CONTENT=$(sed -n '/^cleanup_on_exit()/,/^trap cleanup_on_exit EXIT/p' /home/user/irongate/irongate-install.sh)
echo "$TRAP_CONTENT" | grep -q "systemctl restart php.*-fpm" && echo "$TRAP_CONTENT" | grep -A3 "systemctl restart php.*-fpm" | grep -q "sleep"
test_result "Trap has sleep after PHP-FPM restart before nginx" $?

# Test 3: Check trap verifies nginx started
echo ""
echo "Test 3: Trap function verifies nginx actually started"
grep -q "systemctl is-active.*nginx" /home/user/irongate/irongate-install.sh
test_result "Trap checks if nginx is active" $?

# Test 4: Check trap has nginx retry logic
echo ""
echo "Test 4: Trap function has nginx retry logic"
grep -q "nginx failed to start, retrying" /home/user/irongate/irongate-install.sh
test_result "Trap has nginx retry message and logic" $?

# Test 5: Check auto-updater verifies installer exit code
echo ""
echo "Test 5: Auto-updater checks installer exit status"
grep -q "if bash.*SCRIPT_PATH.*LOG_FILE.*then" /home/user/irongate/irongate-install.sh
test_result "Auto-updater checks bash exit status" $?

# Test 6: Check auto-updater has recovery mechanism
echo ""
echo "Test 6: Auto-updater has service recovery mechanism"
grep -q "RECOVERY.*nginx not running" /home/user/irongate/irongate-install.sh
test_result "Auto-updater has nginx recovery logic" $?

# Test 7: Check auto-updater verifies services after update
echo ""
echo "Test 7: Auto-updater verifies services after update"
grep -q "Verifying services after update" /home/user/irongate/irongate-install.sh
test_result "Auto-updater verifies services post-update" $?

# Test 8: Check auto-updater has PHP-FPM recovery
echo ""
echo "Test 8: Auto-updater has PHP-FPM recovery"
grep -q "RECOVERY_PHP_VER" /home/user/irongate/irongate-install.sh
test_result "Auto-updater has PHP-FPM recovery variable" $?

# Test 9: Syntax check the bash portions
echo ""
echo "Test 9: Bash syntax validation of trap function"
# Extract trap function and check syntax
TRAP_FUNC=$(sed -n '/^cleanup_on_exit()/,/^}/p' /home/user/irongate/irongate-install.sh | head -60)
echo "$TRAP_FUNC" > /tmp/trap_test.sh
bash -n /tmp/trap_test.sh 2>/dev/null
test_result "Trap function has valid bash syntax" $?
rm -f /tmp/trap_test.sh

# Test 10: Check auto-updater has proper recovery sequence (PHP-FPM before nginx)
echo ""
echo "Test 10: Auto-updater recovery starts PHP-FPM before nginx"
UPDATER_CONTENT=$(sed -n '/Verifying services after update/,/Update complete!/p' /home/user/irongate/irongate-install.sh)
PHP_LINE=$(echo "$UPDATER_CONTENT" | grep -n "RECOVERY_PHP_VER" | head -1 | cut -d: -f1)
NGINX_LINE=$(echo "$UPDATER_CONTENT" | grep -n "RECOVERY.*nginx" | head -1 | cut -d: -f1)
[ -n "$PHP_LINE" ] && [ -n "$NGINX_LINE" ] && [ "$PHP_LINE" -lt "$NGINX_LINE" ]
test_result "PHP-FPM recovery comes before nginx recovery" $?

echo ""
echo "============================================"
echo "Test Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "============================================"

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
