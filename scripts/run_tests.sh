#!/usr/bin/env bash
# 工厂测试门（移植四步之四：测试门命令本地化）——phpunit 全量 + behat（可选）。
# 用法: scripts/run_tests.sh [--no-lock] [phpunit-args...]
#   --no-lock 为工厂链约定旗标（上游 run_tests.sh 的锁语义），本仓无锁，消费并忽略。
# 证据形态：phpunit 逐测试输出 + behat 场景，失败全栈。
# 退出码收敛到 0/1（mutation judge 语义域）：任何非零（含 127 未装依赖）= 门红。
set -u -o pipefail
ARGS=()
for a in "$@"; do
  [ "$a" = "--no-lock" ] && continue
  ARGS+=("$a")
done
RC=0
vendor/bin/phpunit "${ARGS[@]+"${ARGS[@]}"}" || RC=$?
# behat 为可选质量面：CI 矩阵未装亦不阻断门形态（phpunit 已是判据锚）。
if [ -x vendor/bin/behat ]; then
  vendor/bin/behat || RC=$?
fi
if [ "$RC" -ne 0 ]; then
  exit 1
fi
exit 0
