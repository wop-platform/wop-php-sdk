#!/usr/bin/env python3
"""docstring 门检查器（wop-php-sdk，统一契约 2026-08-31）。

度量口径：
  对外 API = 顶层 class/interface/trait/enum + public 方法 → 要求 100% 有 phpdoc；
  内部 API = protected/private 方法 → 要求 ≥80%（空集 = 达标）。
docstring 判定：声明前紧邻 phpdoc 块——前一非空行以 ``/**`` 开头（单行块），
或前一非空行为块尾 ``*/`` 且向上连续注释行回到 ``/**`` 行；块与声明之间无空行。
扫描面：git ls-files 枚举 src/ 下 .php（排除 tests/、示例、生成物）。

用法：
  scripts/docstring_gate.py           # 全量检查：exit 0 达标 / 1 未达标
  scripts/docstring_gate.py --json    # JSON 统计输出（同退出码语义）
  scripts/docstring_gate.py --self-test  # 负控制自测（坏输入必须被检出）
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# git 环境密闭（与 .factory/mutations/run.py 同理）：剥除仓库发现变量，
# 防 hook 导出的 GIT_DIR 等劫持 `git -C`/cwd 语义。
_GIT_DISCOVERY_VARS = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
)
_GIT_ENV = {k: v for k, v in os.environ.items() if k not in _GIT_DISCOVERY_VARS}

# 顶层类型声明：class/interface/trait/enum（含 abstract/final/readonly 修饰）
CLASS_RE = re.compile(
    r"^\s*(?:abstract\s+|final\s+|readonly\s+)*(class|interface|trait|enum)\s+(\w+)")
# 方法声明：仅匹配行首修饰词前缀（闭包 `$f = function`、`=> static function`
# 等带前缀形态不命中）；可见性缺省按 PHP 语义视为 public
METHOD_RE = re.compile(
    r"^\s*((?:(?:abstract|final|public|protected|private|static|readonly)\s+)*"
    r")function\s+&?\s*(\w+)\s*\(")

INTERNAL_COVERAGE_MIN = 0.80


@dataclass
class Symbol:
    """一个可文档化声明。"""

    path: str
    line: int  # 1-based
    name: str
    kind: str  # "external" | "internal"
    has_doc: bool


def _has_docblock(lines: list[str], decl_idx: int) -> bool:
    """decl_idx（0-based 声明行）前一非空行是否构成紧邻 phpdoc 块。"""
    i = decl_idx - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    return False if i < 0 else lines[i].strip().startswith("/**")


def scan_lines(rel_path: str, text: str) -> list[Symbol]:
    """逐行扫描单个 PHP 源文件，产出符号清单。"""
    lines = text.splitlines()
    symbols: list[Symbol] = []
    for idx, line in enumerate(lines):
        if m := METHOD_RE.match(line):
            modifiers, name = m.group(1), m.group(2)
            visibility = next(
                (
                    mod
                    for mod in modifiers.split()
                    if mod in ("public", "protected", "private")
                ),
                "public",
            )
            kind = "internal" if visibility in ("protected", "private") else "external"
            symbols.append(Symbol(rel_path, idx + 1, name, kind, _has_docblock(lines, idx)))
            continue
        if c := CLASS_RE.match(line):
            kind, name = "external", c.group(2)
            symbols.append(Symbol(rel_path, idx + 1, name, kind, _has_docblock(lines, idx)))
    return symbols


def enumerate_php_files() -> list[str]:
    """git ls-files 枚举 src/ 下被跟踪的 .php（防未跟踪文件混入扫描面）。"""
    proc = subprocess.run(
        ["git", "ls-files", "--", "src"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_GIT_ENV)
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files 失败: {proc.stderr.strip()}")
    return sorted(f for f in proc.stdout.splitlines() if f.endswith(".php"))


def collect_symbols() -> list[Symbol]:
    """全扫描面符号收集。"""
    symbols: list[Symbol] = []
    for rel in enumerate_php_files():
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        symbols.extend(scan_lines(rel, text))
    return symbols


def _has_docblock(lines: list[str], decl_idx: int) -> bool:
    """decl_idx（0-based 声明行）前一非空行是否构成紧邻 phpdoc 块。

    两种合法形态：单行块（前一非空行本身以 ``/**`` 开头）；多行块（前一非空
    行为块尾 ``*/``，向上经连续 ``*`` 注释行回到 ``/**`` 行，全程无空行、
    无非注释行穿插——空行间隔的 docblock 不算紧邻）。
    """
    i = decl_idx - 1
    if i < 0:
        return False
    if lines[i].strip() == "":
        return False  # 声明紧上方是空行：docblock 与声明间隔 → 不算紧邻
    stripped = lines[i].strip()
    if stripped.startswith("/**"):
        return True
    if not stripped.endswith("*/"):
        return False
    while i >= 0:
        s = lines[i].strip()
        if s == "":
            return False
        if s.startswith("/**"):
            return True
        if s.startswith("*"):
            i -= 1
            continue
        return False
    return False

@dataclass
class GateResult:
    """门判定结果。"""

    external_total: int
    external_missing: list[Symbol]
    internal_total: int
    internal_missing: list[Symbol]

    @property
    def ok(self) -> bool:
        if self.external_missing:
            return False
        if self.internal_total and self.internal_missing:
            covered = 1 - len(self.internal_missing) / self.internal_total
            if covered < INTERNAL_COVERAGE_MIN:
                return False
        return True


def judge(symbols: list[Symbol]) -> GateResult:
    ext = [s for s in symbols if s.kind == "external"]
    inn = [s for s in symbols if s.kind == "internal"]
    return GateResult(
        external_total=len(ext),
        external_missing=[s for s in ext if not s.has_doc],
        internal_total=len(inn),
        internal_missing=[s for s in inn if not s.has_doc],
    )


# ── 负控制自测（--self-test）────────────────────────────────────────
# 已知坏输入：删除/缺失 docstring 的片段，检查逻辑必须判红（非零）。

_BAD_PHP = """<?php

namespace Wop\\Sdk;

class MissingDoc
{
    public function exposed(): void
    {
    }
}
"""

_GOOD_PHP = """<?php

namespace Wop\\Sdk;

/**
 * 全部符号均有紧邻 phpdoc。
 */
interface AllDocumented
{
    /**
     * 多行 docblock 的公开方法。
     */
    public function multiLine(): void;

    /** 单行 docblock 的公开方法。 */
    public function singleLine(): void;
}
/** 好例子的第二个类型声明。 */
final class AllDocumentedToo
{
    /** 内部方法。 */
    private function hidden(): void
    {
    }
}
"""

_BLANK_GAP_PHP = """<?php

/**
 * docblock 与声明之间隔空行 → 不算紧邻。
 */

class GapIsNotAdjacency
{
    public function separated(): void
    {
    }
}
"""


def self_test() -> int:
    """负控制：坏输入必须被检出（模拟判定非零），好输入必须全绿。"""
    failures: list[str] = []

    bad = judge(scan_lines("fix-bad.php", _BAD_PHP))
    bad_names = {s.name for s in bad.external_missing}
    if not bad.external_missing or not {"MissingDoc", "exposed"} <= bad_names:
        failures.append(f"坏输入未检出: 缺失清单={sorted(bad_names)}")
    if bad.ok:
        failures.append("坏输入判绿（负控制失效：缺失 docstring 必须非零）")

    good = judge(scan_lines("fix-good.php", _GOOD_PHP))
    if good.external_missing or good.internal_missing:
        failures.append(
            f"好输入误报: 对外缺={[(s.name) for s in good.external_missing]} "
            f"内部缺={[(s.name) for s in good.internal_missing]}")
    if not good.ok:
        failures.append("好输入判红（多行/单行 docblock 应计入已文档）")

    gap = judge(scan_lines("fix-gap.php", _BLANK_GAP_PHP))
    gap_names = {s.name for s in gap.external_missing}
    if "separated" not in gap_names or "GapIsNotAdjacency" not in gap_names:
        failures.append(f"空行间隔的 docblock 未被判定缺失: {sorted(gap_names)}")

    if failures:
        for f in failures:
            print(f"self-test FAIL: {f}", file=sys.stderr)
        return 1
    print("self-test PASS: 负控制（坏输入判红）+ 好输入全绿 + 空行间隔规则")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="负控制自测")
    parser.add_argument("--json", action="store_true", help="JSON 统计输出")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        result = judge(collect_symbols())
    except (RuntimeError, OSError) as exc:
        print(f"docstring gate 配置/扫描面错误: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "ok": result.ok,
            "external_total": result.external_total,
            "external_documented": result.external_total - len(result.external_missing),
            "external_missing": [f"{s.path}:{s.line} {s.name}" for s in result.external_missing],
            "internal_total": result.internal_total,
            "internal_documented": result.internal_total - len(result.internal_missing),
            "internal_missing": [f"{s.path}:{s.line} {s.name}" for s in result.internal_missing],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for s in result.external_missing:
            print(f"{s.path}:{s.line} {s.name} [对外]")
        for s in result.internal_missing:
            print(f"{s.path}:{s.line} {s.name} [内部]")
        ext_cov = result.external_total - len(result.external_missing)
        int_cov = result.internal_total - len(result.internal_missing)
        print(f"统计: 对外 {ext_cov}/{result.external_total}、"
              f"内部 {int_cov}/{result.internal_total}")
        if not result.ok:
            print("未达标: 对外须 100%、内部须 ≥80%")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
