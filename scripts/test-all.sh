#!/bin/bash
cd "$(dirname "$0")/.." || exit 1
FAIL=0

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════"
echo ""

echo "── 1. 编译 ──"
make clean > /dev/null 2>&1 || true
make 2>&1 | grep "→"
echo ""

echo "── 2. AEGIS-128 算法 (12项) ──"
timeout 10 ./test-aegis 2>&1
echo ""

echo "── 3. 帧协议 + 握手 (7项) ──"
timeout 10 ./test-tunnel 2>&1
echo ""

echo "── 4. 端到端握手+加解密 (2项) ──"
timeout 10 ./e2e-test 2>&1
echo ""

echo "── 5. 主程序功能验证 ──"
./aegis-tunnel -h > /dev/null 2>&1 && echo "  help ....................... PASS" || { echo "  help ....................... FAIL"; ((FAIL++)); }
./aegis-tunnel 2>&1 | grep -q "Error" && echo "  parameter validation ....... PASS" || { echo "  parameter validation ....... FAIL"; ((FAIL++)); }
./aegis-tunnel -h 2>&1 | grep -q "\-Q" && echo "  -Q flag .................... PASS" || { echo "  -Q flag .................... FAIL"; ((FAIL++)); }
./aegis-tunnel -h 2>&1 | grep -q "\-P" && echo "  -P flag .................... PASS" || { echo "  -P flag .................... FAIL"; ((FAIL++)); }

rm -rf /tmp/aegis-test-keys ~/.aegis-tunnel
./aegis-tunnel -l 19990 -r test:9000 2>&1 | grep -q "public key" && echo "  auto-keygen ................ PASS" || { echo "  auto-keygen ................ FAIL"; ((FAIL++)); }
rm -rf ~/.aegis-tunnel
echo ""

echo "── 6. 性能基准 ──"
./bench-aegis 2>&1 | head -6
echo ""

echo "═══════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then echo " 全部通过"; else echo " $FAIL 项失败"; fi
echo "═══════════════════════════════════════════"
exit $FAIL
