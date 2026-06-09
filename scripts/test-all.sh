#!/bin/bash
# AEGIS-Tunnel 全量测试脚本
# 运行方式: bash scripts/test-all.sh
cd "$(dirname "$0")/.." || exit 1

PASS=0
FAIL=0
TIMEOUT=10

run_test() {
    local name="$1" cmd="$2"
    printf "  %-55s ... " "$name"
    if eval "timeout $TIMEOUT $cmd" > /dev/null 2>&1; then
        echo "PASS"; PASS=$((PASS + 1))
    else
        echo "FAIL"; FAIL=$((FAIL + 1))
    fi
}

echo "═══════════════════════════════════════════"
echo " AEGIS-Tunnel Full Test Suite"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "═══════════════════════════════════════════"
echo ""

# ── 0. 准备测试密钥 ──
echo "── 0. 准备测试密钥 ──"
mkdir -p /tmp/aegis-test
dd if=/dev/urandom bs=16 count=1 of=/tmp/aegis-test/psk.key 2>/dev/null
chmod 400 /tmp/aegis-test/psk.key
echo "  PSK: /tmp/aegis-test/psk.key"
echo ""

# ── 1. 编译 ──
echo "── 1. 编译 ──"
make clean > /dev/null 2>&1 || true
make test-aegis test-tunnel e2e-test bench-aegis aegis-tunnel \
    aegis-tunnel-keygen 2>&1 | tail -5
echo ""

# ── 2. 算法测试 ──
echo "── 2. AEGIS-128 算法 (13项) ──"
timeout 10 ./test-aegis 2>&1
echo ""

# ── 3. 协议测试 ──
echo "── 3. 帧协议 + PSK 握手 (7项) ──"
timeout 10 ./test-tunnel 2>&1
echo ""

# ── 4. 端到端测试 ──
echo "── 4. 端到端握手+加解密 (2项) ──"
timeout 10 ./e2e-test 2>&1
echo ""

# ── 5. 主程序 smoke test ──
echo "── 5. 主程序功能验证 ──"
run_test "帮助输出"          "./aegis-tunnel -h > /dev/null"
run_test "参数校验"          "./aegis-tunnel 2>&1 | grep -q 'Error'"
run_test "密钥生成工具"      "./aegis-tunnel-keygen /tmp/aegis-test/keygen"
run_test "PSK 文件读取"     "./aegis-tunnel -l 19990 -r 127.0.0.1:80 -f /tmp/aegis-test/psk.key -h > /dev/null"
run_test "TUN 参数"         "./aegis-tunnel -h 2>&1 | grep -q '\-T'"
run_test "日志参数"         "./aegis-tunnel -h 2>&1 | grep -q '\-v'"
run_test "配置文件参数"     "./aegis-tunnel -h 2>&1 | grep -q '\-C'"
echo ""

# ── 6. 性能基准（仅显示，不判定）──
echo "── 6. 性能基准 ──"
./bench-aegis 2>&1 | head -7
echo ""

# ── 总结 ──
echo "═══════════════════════════════════════════"
echo " 测试完成: $PASS 通过, $FAIL 失败"
echo "═══════════════════════════════════════════"

exit $FAIL
