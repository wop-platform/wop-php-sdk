#!/usr/bin/env bash
# pre-push 测试门（awesome-rules .lefthook/run-tests.sh 的项目自定义入口，入库共享）
# 全量 phpunit（+已装 behat）；失败即阻断 push。跳过: git push --no-verify
# 覆盖率红线（行/分支 ≥98%）不在此重复跑——path-coverage 产物重，由 CI 侧
# .ci/coverage-gate.php 承担；本地测试门 + CI 覆盖率门双层，门禁语义不变。
set -u
cd "$(git rev-parse --show-toplevel)"
exec bash scripts/run_tests.sh "$@"
