#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo "═══════════════════════════════════════════"
echo ""

# ── 1. 编译 ──
echo "── 1. 编译 ──"
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel 2>&1 | tail -3
echo ""

# ── 2. 算法测试 ──
echo "── 2. AEGIS-128 算法 (13项) ──"
timeout 10 ./test-aegis
echo ""

# ── 3. 协议测试 ──
echo "── 3. 帧协议 + PSK 握手 (7项) ──"
timeout 10 ./test-tunnel
echo ""

# ── 4. 端到端测试 ──
echo "── 4. 端到端握手+加解密 (2项) ──"
timeout 10 ./e2e-test
echo ""

# ── 5. 非对称握手测试 ──
echo "── 5. 非对称握手 (2项) ──"
if [ -f ./test-asymmetric ]; then
    timeout 10 ./test-asymmetric
else
    echo "  (跳过：需先 make test-asymmetric 编译)"
fi
echo ""

# ── 6. 性能基准 ──
echo "── 6. 性能基准 ──"
./bench-aegis 2>&1 | head -7
echo ""

# ── 7. 主程序 smoke test ──
echo "── 7. 主程序功能验证 ──"
./aegis-tunnel -h > /dev/null 2>&1 && echo "  help output ........................ PASS" || echo "  help output ........................ FAIL"
echo ""

echo "═══════════════════════════════════════════"
echo " 测试完成"
echo "═══════════════════════════════════════════"
