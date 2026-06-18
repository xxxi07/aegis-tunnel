#!/bin/bash
cd "$(dirname "$0")/.." || exit 1
FAIL=0

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════"
echo ""

echo "── 1. Build ──"
make clean > /dev/null 2>&1 || true
make 2>&1 | grep "→"
echo ""

echo "── 2. AEGIS-128 Algorithm (13 tests) ──"
timeout 10 ./test-aegis 2>&1
echo ""

echo "── 3. Frame Protocol + Handshake (8 tests) ──"
timeout 10 ./test-tunnel 2>&1
echo ""

echo "── 4. End-to-End Handshake + Encrypt/Decrypt (2 tests) ──"
timeout 10 ./e2e-test 2>&1
echo ""

echo "── 5. Main Program Validation ──"
./aegis-tunnel -h > /dev/null 2>&1 && echo "  help ....................... PASS" || { echo "  help ....................... FAIL"; ((FAIL++)); }
./aegis-tunnel 2>&1 | grep -q "Error" && echo "  parameter validation ....... PASS" || { echo "  parameter validation ....... FAIL"; ((FAIL++)); }
./aegis-tunnel -h 2>&1 | grep -q "\-Q" && echo "  -Q flag .................... PASS" || { echo "  -Q flag .................... FAIL"; ((FAIL++)); }
./aegis-tunnel -h 2>&1 | grep -q "\-P" && echo "  -P flag .................... PASS" || { echo "  -P flag .................... FAIL"; ((FAIL++)); }

rm -rf /tmp/aegis-test-keys ~/.aegis-tunnel
./aegis-tunnel -l 19990 -r test:9000 2>&1 | grep -q "public key" && echo "  auto-keygen ................ PASS" || { echo "  auto-keygen ................ FAIL"; ((FAIL++)); }
rm -rf ~/.aegis-tunnel
echo ""

echo "── 6. Performance Benchmark ──"
./bench-aegis 2>&1 | head -6
echo ""

echo "═══════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then echo " All tests passed"; else echo " $FAIL test(s) failed"; fi
echo "═══════════════════════════════════════════"
exit $FAIL
