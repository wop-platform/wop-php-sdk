#!/bin/bash
# 可移植性探测门禁：可执行/配置面内拒绝机器特定绝对路径（其他机器不可访问）。
# 本地与 CI 共用（CI 步骤直接调用本脚本）。
#
# 拒绝：个人目录、包管理器前缀、Windows 盘符（pattern 拼接构造，避免自噬）。
# 允许：/dev/null 与 /tmp（POSIX 标准路径，runner/开发机必有）、sys_get_temp_dir()（运行期 API）。
# 豁免：`:N:PATH=` 赋值行——环境规范而非文件路径引用。cron 环境 PATH 兜底链
#   含 /opt/homebrew 等候选前缀属 POSIX 惯例（上游 cron-dispatch.sh:13），
#   候选路径在无前缀的机器上不存在即跳过，不构成"其他机器不可访问"硬引用。

set -e
cd "$(dirname "$0")/.."

patterns="/Use""rs/|/opt/home""brew|/usr/local/(bin|lib|php)|/hom""e/[^/[:space:]]|C:\\\\"

hits=$(grep -rnE "$patterns" \
  --include='*.php' --include='*.py' --include='*.sh' --include='*.yml' \
  --include='*.yaml' --include='*.xml' --include='*.json' --include='*.feature' \
  src tests features scripts .factory .ci behat.yml phpunit.xml composer.json .github \
  2>/dev/null | grep -v '/portability-gate\.sh:' | grep -vE ':[0-9]+:PATH=' || true)

if [ -n "$hits" ]; then
  echo "::error::检出机器特定绝对路径（其他机器不可访问），请改为运行期解析："
  echo "$hits"
  exit 1
fi
echo "portability gate: clean"
