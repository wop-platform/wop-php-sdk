#!/bin/bash
# 质量闭环驱动脚本（herdr pane 内执行）
set -e
cd /Users/dreambt/sources/open-platform/wop-php-sdk

PHP_BIN=/opt/homebrew/bin/php
COMPOSER_PHAR=/tmp/composer-quality.phar
if [ ! -f "$COMPOSER_PHAR" ]; then
  curl -fsSL https://getcomposer.org/download/latest-stable/composer.phar -o "$COMPOSER_PHAR"
fi

step="$1"
case "$step" in
  behat-install)
    "$PHP_BIN" "$COMPOSER_PHAR" require --dev behat/behat --no-interaction --with-all-dependencies
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
