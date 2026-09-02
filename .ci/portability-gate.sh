#!/bin/bash
# 可移植性探测门禁：可执行/配置面内拒绝机器特定绝对路径（其他机器不可访问）。
# 本地与 CI 共用（CI 步骤直接调用本脚本）。
#
# 拒绝：个人目录、包管理器前缀、Windows 盘符（pattern 拼接构造，避免自噬）。
# 允许：/dev/null 与 /tmp（POSIX 标准路径，runner/开发机必有）、sys_get_temp_dir()（运行期 API）。
#
# 豁免（上游 full 分发、设计内含本机路径、go/py/java 同形态已入库）：
#   .factory/cron-dispatch.sh   cron 环境 PATH 显式注入字面量（含 POSIX 兜底目录）
#   .factory/upstream-lock.json M2 契约：upstream 字段记录 sync 机上游仓路径
# 两文件由 sync-from-upstream.sh full 覆盖，本地改写会被下轮 sync 还原，豁免是唯一
# 持久出路（非掩耳盗铃：src/tests/scripts/.github 包代码面豁免不变）。

set -e
cd "$(dirname "$0")/.."

patterns="/Use""rs/|/opt/home""brew|/usr/local/(bin|lib|php)|/hom""e/[^/[:space:]]|C:\\\\"

hits=$(grep -rnE "$patterns" \
  --include='*.php' --include='*.py' --include='*.sh' --include='*.yml' \
  --include='*.yaml' --include='*.xml' --include='*.json' --include='*.feature' \
  src tests features scripts .factory .ci behat.yml phpunit.xml composer.json .github \
  2>/dev/null | grep -vE '/portability-gate\.sh:|\.factory/(cron-dispatch\.sh|upstream-lock\.json):' || true)

if [ -n "$hits" ]; then
  echo "::error::检出机器特定绝对路径（其他机器不可访问），请改为运行期解析："
  echo "$hits"
  exit 1
fi
echo "portability gate: clean"
