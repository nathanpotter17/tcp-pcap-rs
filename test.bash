#!/bin/bash
#
# Cross-platform test script for DGTCP
# Works on: Linux, macOS, Windows (Git Bash/MSYS2/WSL)
#

BINARY="./target/release/tcp-server"
SERVER_ADDR="127.0.0.1:9090"
TEST_POOL="test_pool_$$"
SERVER_PID=""

# Windows executable extension
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OS" == "Windows_NT" ]]; then
    BINARY="./target/release/tcp-server.exe"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}► $1${NC}"; }

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

echo "═══════════════════════════════════════════════════════"
echo "  DGTCP Hardened Authentication Test Suite"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Platform: ${OSTYPE:-unknown}"
echo "Binary:   $BINARY"
echo ""

# Check binary exists
if [ ! -f "$BINARY" ]; then
    info "Binary not found, attempting build..."
    cargo build --release || {
        fail "Build failed"
        exit 1
    }
fi

# Clean previous test state
rm -rf db/ 2>/dev/null || true

TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# TEST 1: Successful mutual authentication
# ============================================================================
echo ""
info "TEST 1: Successful mutual authentication"

$BINARY server $SERVER_ADDR $TEST_POOL &
SERVER_PID=$!
sleep 3

CLIENT_OUTPUT=$($BINARY client $SERVER_ADDR $TEST_POOL 2>&1)
CLIENT_EXIT=$?

kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

if [ $CLIENT_EXIT -eq 0 ]; then
    pass "Mutual authentication successful"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Client failed with exit code $CLIENT_EXIT"
    echo "$CLIENT_OUTPUT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# TEST 2: Pool mismatch rejection
# ============================================================================
echo ""
info "TEST 2: Pool mismatch rejection (security)"

$BINARY server $SERVER_ADDR $TEST_POOL &
SERVER_PID=$!
sleep 3

# Client uses WRONG pool - must fail
$BINARY client $SERVER_ADDR "wrong_pool" >/dev/null 2>&1
WRONG_EXIT=$?

kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

if [ $WRONG_EXIT -ne 0 ]; then
    pass "Pool mismatch correctly rejected"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "SECURITY: Wrong pool was accepted!"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# TEST 3: Identity persistence
# ============================================================================
echo ""
info "TEST 3: Identity persistence across restarts"

# First run
$BINARY server $SERVER_ADDR $TEST_POOL > /tmp/srv1.log 2>&1 &
SERVER_PID=$!
sleep 2
kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

DID1=$(grep -o 'did:diagon:[a-f0-9]*' /tmp/srv1.log 2>/dev/null | head -1)

# Second run
$BINARY server $SERVER_ADDR $TEST_POOL > /tmp/srv2.log 2>&1 &
SERVER_PID=$!
sleep 2
kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

DID2=$(grep -o 'did:diagon:[a-f0-9]*' /tmp/srv2.log 2>/dev/null | head -1)

if [ -n "$DID1" ] && [ "$DID1" = "$DID2" ]; then
    pass "Server DID persisted correctly"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "DID not persisted (Run1: $DID1, Run2: $DID2)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# TEST 4: Multiple sequential connections
# ============================================================================
echo ""
info "TEST 4: Multiple client connections"

$BINARY server $SERVER_ADDR $TEST_POOL &
SERVER_PID=$!
sleep 3

SUCCESS=0
for i in 1 2 3; do
    if $BINARY client $SERVER_ADDR $TEST_POOL >/dev/null 2>&1; then
        SUCCESS=$((SUCCESS + 1))
    fi
    sleep 1
done

kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

if [ $SUCCESS -eq 3 ]; then
    pass "All 3 connections succeeded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    fail "Only $SUCCESS/3 connections succeeded"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "═══════════════════════════════════════════════════════"
echo -e "  Passed: ${GREEN}$TESTS_PASSED${NC}  Failed: ${RED}$TESTS_FAILED${NC}"
echo "═══════════════════════════════════════════════════════"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi