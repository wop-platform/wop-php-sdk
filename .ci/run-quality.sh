#!/bin/bash
# 质量闭环驱动脚本（可移植：路径全部运行期解析，无机器特定硬编码）
set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# composer 解析：PATH 优先；缺失则下载 phar 到仓库内 .cache/（gitignore，避免 /tmp 只读或共享互踩）
run_composer() {
  if command -v composer >/dev/null 2>&1; then
    composer "$@"
  else
    local phar="$REPO_ROOT/.cache/composer.phar"
    if [ ! -f "$phar" ]; then
      mkdir -p "$REPO_ROOT/.cache"
      curl -fsSL https://getcomposer.org/download/latest-stable/composer.phar -o "$phar"
    fi
    php "$phar" "$@"
  fi
}

step="$1"
case "$step" in
  behat-install)
    run_composer require --dev behat/behat --no-interaction --with-all-dependencies
    vendor/bin/behat --version
    ;;
  behat)
    vendor/bin/behat
    ;;
  behat-pretty)
    vendor/bin/behat --format pretty
    ;;
  *)
    echo "usage: $0 behat-install|behat|behat-pretty"
    exit 2
    ;;
esac
