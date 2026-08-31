"""docstring 门检查器的外部驱动测试（scripts/docstring_gate.py）。

与 --self-test 互补：self-test 用内嵌样本做负控制，本文件按函数/分支逐一
驱动检查器全部路径——docstring 归属判定、符号扫描、扫描面枚举、阈值判定、
CLI 行为（exit 0/1/2、--json、--self-test、错误参数）。

注意：源文件 61 行与 113 行各有一个 `_has_docblock`，后者在导入时覆盖前者；
模块属性生效的是 113 行版（见 test_effective_docblock_is_second_definition），
61 行旧版仅通过编译其源码段单独驱动（见 test_legacy_first_docblock_*）。
"""
# spec:DG-1 对外 API 100% 红线 → 阈值与判定测试(见下方用例)
# spec:DG-2 内部 ≥80%(空内部集=达标) → 阈值边界测试
# spec:DG-3 docstring 归属判定(注释形态/空行/组注释不覆盖) → 判定测试
# spec:DG-4 CLI 无参 exit 0/1 + 逐符号缺失清单 + 统计 → main/CLI 测试
# spec:DG-5 --self-test 负控制(先红后绿) → self_test 测试
# spec:DG-6 扫描面 = git ls-files 枚举(反作弊) → 扫描面测试
# spec:DG-7 factory-local.json docstring_gate_cmd 禁引号/反斜杠 → 上游 test_factory_lib.py TestDocstringGateWords
# spec:DG-8 defects.json D-xx gate=docstring 击杀 → mutations/defects.json D-01/D-02 PASS
# spec:DG-10 mutations judge 门域 0/1 → 上游 test_mutations_run.py TestDocstringGateJudge


from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docstring_gate as gate  # noqa: E402


def _mk_symbol(name, kind, has_doc):
    return gate.Symbol("src/x.php", 1, name, kind, has_doc)


# ── 符号与常量 ───────────────────────────────────────────────────────


def test_symbol_is_plain_dataclass():
    sym = gate.Symbol(path="src/A.php", line=3, name="Foo", kind="external", has_doc=True)
    assert (sym.path, sym.line, sym.name, sym.kind, sym.has_doc) == (
        "src/A.php", 3, "Foo", "external", True)
    assert gate.INTERNAL_COVERAGE_MIN == 0.80


def test_regex_contracts():
    # 类型声明四类 + abstract/final/readonly 修饰组合
    for decl in ("class Foo", "interface I", "trait T", "enum E",
                 "abstract class A", "final class B", "readonly class C",
                 "abstract final readonly class D", "enum Suit"):
        assert gate.CLASS_RE.match(decl), decl
    assert not gate.CLASS_RE.match("classy Foo")
    assert not gate.CLASS_RE.match("$x = new class")
    # 方法：修饰词 + 引用返回 &；可见性缺省合法
    for decl in ("function f(", "public function f(", "static protected function f(",
                 "private static function f(", "function &f(", "function f ("):
        assert gate.METHOD_RE.match(decl), decl
    # 闭包/箭头函数带前缀，不命中
    for decl in ("$f = function () use ($x) {", "fn($x) => $x * 2",
                 "=> static function (): void {", "$map[strlen('function')] = 1;"):
        assert not gate.METHOD_RE.match(decl), decl


# ── _has_docblock（生效的 113 行版）──────────────────────────────────


def test_effective_docblock_is_second_definition():
    # 区分两版行为的样本：docblock 与声明间空行——旧版(61)跳过空行判 True，
    # 新版(113)要求紧邻判 False。模块属性必须是新版。
    assert gate._has_docblock.__code__.co_firstlineno >= 100
    assert gate._has_docblock(["/**", "", "decl"], 2) is False


def test_docblock_decl_at_file_start():
    assert gate._has_docblock(["class Foo"], 0) is False


def test_docblock_blank_line_directly_above():
    assert gate._has_docblock(["/** doc */", "", "class Foo"], 2) is False


def test_docblock_single_line_block():
    assert gate._has_docblock(["/** doc */", "class Foo"], 1) is True


def test_docblock_multiline_block():
    lines = ["<?php", "/**", " * 摘要。", " *", " */", "class Foo"]
    assert gate._has_docblock(lines, 5) is True


def test_docblock_prev_line_is_code_or_line_comment():
    # 前一非空行既非 /** 开头也非 */ 结尾 → 非紧邻 docblock
    assert gate._has_docblock(["use Wop\\Sdk;", "class Foo"], 1) is False
    assert gate._has_docblock(["// 行注释", "class Foo"], 1) is False


def test_docblock_plain_block_comment_is_not_phpdoc():
    # /* … */（非 /**）块尾向上遇到非 * 前缀行 → False
    assert gate._has_docblock(["/* 普通", "   块注释 */", "class Foo"], 2) is False


def test_docblock_block_gap_by_blank_inside():
    # 块尾向上途中出现空行 → 块不完整
    assert gate._has_docblock(["/**", "", " */", "class Foo"], 3) is False


def test_docblock_block_gap_by_code_inside():
    # 块尾向上途中穿插代码行 → False
    assert gate._has_docblock(["/**", "$x = 1;", " */", "class Foo"], 3) is False


def test_docblock_block_tail_without_opener_runs_off_top():
    # 一路 * 行向上直到文件顶也没有 /** 行 → False（循环耗尽路径）
    assert gate._has_docblock([" * 残缺", " */", "class Foo"], 2) is False


# ── _has_docblock（61 行旧版，已被同名定义覆盖，编译源码段驱动）────


def _legacy_docblock():
    """提取文件中第一个 `_has_docblock`（61 行版）并独立编译执行。

    以原文件名为 co_filename 编译，且前置空行把段内行号对齐到原文件，
    coverage 才能把命中行归属到源文件 63-68 行，覆盖被覆盖前的旧版实现体。
    """
    path = Path(gate.__file__)
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "_has_docblock")
    segment = "\n".join(src.splitlines()[fn.lineno - 1:fn.end_lineno])
    code = compile("\n" * (fn.lineno - 1) + segment, str(path), "exec")
    ns: dict = {}
    exec(code, ns)  # noqa: S102
    return ns["_has_docblock"]


def test_legacy_first_docblock_behaviour_and_shadowing():
    legacy = _legacy_docblock()
    assert legacy.__code__.co_firstlineno == 61  # 段行号已对齐原文件
    # 旧版跳过空行后回看：紧邻空行不算间隔
    assert legacy(["/**", "", "decl"], 2) is True          # 空行回溯 + 命中 /**
    assert legacy(["/** doc */", "decl"], 1) is True        # 单行块直接命中
    assert legacy(["use Foo;", "decl"], 1) is False         # 前行非注释
    assert legacy(["decl"], 0) is False                     # 文件首行（i < 0）
    # 生效版本与旧版语义不同（空行判定），证明覆盖关系真实存在
    assert gate._has_docblock(["/**", "", "decl"], 2) is False


# ── scan_lines ──────────────────────────────────────────────────────


def test_scan_class_declarations_are_external():
    text = "\n".join([
        "<?php",
        "namespace Wop\\Sdk;",
        "/** 类文档。 */",
        "abstract class Abs { }",
        "/** 接口文档。 */",
        "final class Fin { }",
        "/** trait 文档。 */",
        "trait Beh { }",
        "/** 枚举文档。 */",
        "enum Suit: string { }",
        "class Bare { }",  # 无 docblock
    ])
    syms = gate.scan_lines("src/kinds.php", text)
    by_name = {s.name: s for s in syms}
    assert set(by_name) == {"Abs", "Fin", "Beh", "Suit", "Bare"}
    assert all(s.kind == "external" for s in syms)
    assert by_name["Bare"].has_doc is False
    assert by_name["Abs"].has_doc is True
    assert by_name["Suit"].line == 10  # 1-based 行号
    assert by_name["Abs"].path == "src/kinds.php"


def test_scan_method_visibility_and_defaults():
    text = "\n".join([
        "<?php",
        "class S {",
        "    /** 公开。 */",
        "    public function a() {}",
        "    protected function b() {}",
        "    /** 私有。 */",
        "    private function c() {}",
        "    static protected function d() {}",
        "    function e() {}",          # 缺省可见性 = public
        "    public static function f() {}",
        "    final private function g() {}",
        "    /** 引用返回。 */",
        "    public function &h() {}",
        "}",
    ])
    syms = {s.name: s for s in gate.scan_lines("src/m.php", text)}
    assert set(syms) == {"S"} | set("abcdefgh")
    assert syms["S"].kind == "external" and syms["S"].has_doc is False
    assert syms["a"].kind == "external" and syms["a"].has_doc is True
    assert syms["b"].kind == "internal" and syms["b"].has_doc is False
    assert syms["c"].kind == "internal" and syms["c"].has_doc is True
    assert syms["d"].kind == "internal"   # 修饰词顺序无关
    assert syms["e"].kind == "external"   # 缺省 = public → 对外
    assert syms["f"].kind == "external"
    assert syms["g"].kind == "internal"
    assert syms["h"].has_doc is True      # & 引用返回仍识别


def test_scan_skips_closures_and_arrows():
    text = "\n".join([
        "<?php",
        "$f = function ($x) { return $x; };",
        "$g = fn($x) => $x * 2;",
        "$h = static function (): void { };",
        "$fn = 'function';",
    ])
    assert gate.scan_lines("src/closures.php", text) == []


def test_scan_multiline_docblock_adjacency():
    text = "\n".join([
        "<?php",
        "/**",
        " * 多行块。",
        " */",
        "class Adj {",
        "    /**",
        "     * 方法块。",
        "     */",
        "    public function documented() {}",
        "",
        "    /**",
        "     * 与声明隔了空行。",
        "     */",
        "",
        "    public function separated() {}",
        "}",
    ])
    syms = {s.name: s for s in gate.scan_lines("src/adj.php", text)}
    assert syms["Adj"].has_doc is True
    assert syms["documented"].has_doc is True
    assert syms["separated"].has_doc is False


def test_scan_empty_text():
    assert gate.scan_lines("src/empty.php", "") == []


# ── enumerate_php_files / collect_symbols ───────────────────────────


class _FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_enumerate_uses_git_ls_files(monkeypatch):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env")
        return _FakeCompleted(stdout="src/B.php\nsrc/A.php\nsrc/notes.md\nsrc/sub/C.php\n")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    files = gate.enumerate_php_files()
    assert files == ["src/A.php", "src/B.php", "src/sub/C.php"]  # 排序 + 仅 .php
    assert captured["cmd"] == ["git", "ls-files", "--", "src"]
    assert captured["cwd"] == str(gate.REPO_ROOT)
    # git 环境密闭：仓库发现变量被剥除，其余环境保留
    for var in gate._GIT_DISCOVERY_VARS:
        assert var not in captured["env"]
    assert captured["env"].get("PATH") == os.environ.get("PATH")


def test_enumerate_real_repo_integration():
    files = gate.enumerate_php_files()
    assert files, "真实仓库 src/ 扫描面不应为空"
    assert all(f.endswith(".php") and f.startswith("src/") for f in files)
    assert files == sorted(files)


def test_enumerate_git_failure_raises(monkeypatch):
    monkeypatch.setattr(
        gate.subprocess, "run",
        lambda *a, **k: _FakeCompleted(returncode=128, stderr="fatal: not a git repo"))
    with pytest.raises(RuntimeError, match="git ls-files 失败: fatal: not a git repo"):
        gate.enumerate_php_files()


def test_collect_symbols_reads_each_file(monkeypatch, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.php").write_text(
        "<?php\n/** 文档。 */\nclass A\n{\n    public function m() {}\n}\n",
        encoding="utf-8")
    (tmp_path / "src" / "B.php").write_text(
        "<?php\nclass B { }\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "enumerate_php_files", lambda: ["src/B.php", "src/A.php"])
    # 按枚举顺序逐文件扫描（collect 不重排）
    syms = gate.collect_symbols()
    assert [(s.path, s.name) for s in syms] == [
        ("src/B.php", "B"), ("src/A.php", "A"), ("src/A.php", "m")]


def test_collect_symbols_empty_scan(monkeypatch):
    monkeypatch.setattr(gate, "enumerate_php_files", lambda: [])
    assert gate.collect_symbols() == []


# ── judge / GateResult.ok ───────────────────────────────────────────


def test_judge_partitions_and_finds_missing():
    symbols = [
        _mk_symbol("A", "external", True),
        _mk_symbol("B", "external", False),
        _mk_symbol("c", "internal", False),
    ]
    result = gate.judge(symbols)
    assert result.external_total == 2
    assert [s.name for s in result.external_missing] == ["B"]
    assert result.internal_total == 1
    assert [s.name for s in result.internal_missing] == ["c"]


def test_judge_empty_input():
    result = gate.judge([])
    assert result == gate.GateResult(0, [], 0, [])


def test_ok_all_documented():
    symbols = [_mk_symbol("A", "external", True), _mk_symbol("b", "internal", True)]
    assert gate.judge(symbols).ok is True


def test_ok_external_missing_blocks():
    symbols = [_mk_symbol("A", "external", False), _mk_symbol("b", "internal", True)]
    assert gate.judge(symbols).ok is False


def test_ok_empty_internal_set_passes():
    symbols = [_mk_symbol("A", "external", True)]
    assert gate.judge(symbols).ok is True


def test_ok_internal_at_exact_80_percent_boundary():
    # 5 内部缺 1 → 80% 恰达阈值（< 0.80 才判红）→ 绿
    symbols = ([_mk_symbol("A", "external", True)]
               + [_mk_symbol(f"m{i}", "internal", i != 0) for i in range(5)])
    assert gate.judge(symbols).ok is True


def test_ok_internal_below_80_percent_fails():
    # 5 内部缺 2 → 60% < 80% → 红
    symbols = ([_mk_symbol("A", "external", True)]
               + [_mk_symbol(f"m{i}", "internal", i >= 2) for i in range(5)])
    assert gate.judge(symbols).ok is False


def test_ok_internal_missing_within_ratio_passes():
    # 10 内部缺 2 → 80% → 绿
    symbols = [_mk_symbol(f"m{i}", "internal", i >= 2) for i in range(10)]
    assert gate.judge(symbols).ok is True


# ── self_test ───────────────────────────────────────────────────────


def test_self_test_passes(capsys):
    assert gate.self_test() == 0
    assert "self-test PASS" in capsys.readouterr().out


def test_self_test_fails_when_scanner_misses_bad_input(monkeypatch, capsys):
    # 模拟扫描逻辑回归（漏检）：坏输入不再被判红 → self-test 必须报错
    monkeypatch.setattr(gate, "scan_lines", lambda rel, text: [])
    assert gate.self_test() == 1
    err = capsys.readouterr().err
    assert "坏输入未检出" in err
    assert "坏输入判绿" in err
    assert "空行间隔的 docblock 未被判定缺失" in err


def test_self_test_fails_on_false_positives(monkeypatch, capsys):
    # 模拟误报：一切符号均判"缺文档" → 好输入路径必须被 self-test 抓住
    def fake_scan(rel, text):
        return [gate.Symbol(rel, 1, "X", "external", False)]

    monkeypatch.setattr(gate, "scan_lines", fake_scan)
    assert gate.self_test() == 1
    err = capsys.readouterr().err
    assert "好输入误报" in err
    assert "好输入判红" in err


# ── main / CLI ─────────────────────────────────────────────────────


def test_main_self_test_flag(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(gate, "collect_symbols", lambda: called.append(1) or [])
    assert gate.main(["--self-test"]) == 0
    assert "self-test PASS" in capsys.readouterr().out
    assert not called


def test_main_clean_repo_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols",
                        lambda: [_mk_symbol("A", "external", True),
                                 _mk_symbol("b", "internal", True)])
    assert gate.main([]) == 0
    out = capsys.readouterr().out
    assert "统计: 对外 1/1、内部 1/1" in out
    assert "未达标" not in out


def test_main_empty_scan_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols", lambda: [])
    assert gate.main([]) == 0
    assert "统计: 对外 0/0、内部 0/0" in capsys.readouterr().out


def test_main_missing_reports_and_exit_one(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols",
                        lambda: [_mk_symbol("A", "external", False),
                                 _mk_symbol("b", "internal", False)])
    assert gate.main([]) == 1
    out = capsys.readouterr().out
    assert "src/x.php:1 A [对外]" in out
    assert "src/x.php:1 b [内部]" in out
    assert "未达标: 对外须 100%、内部须 ≥80%" in out


def test_main_json_ok(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols",
                        lambda: [_mk_symbol("A", "external", True)]
                        + [_mk_symbol(f"m{i}", "internal", i != 0) for i in range(5)])
    assert gate.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["external_total"] == 1
    assert payload["external_documented"] == 1
    assert payload["external_missing"] == []
    assert payload["internal_total"] == 5
    assert payload["internal_documented"] == 4
    assert payload["internal_missing"] == ["src/x.php:1 m0"]


def test_main_json_missing_exit_one(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols",
                        lambda: [_mk_symbol("A", "external", False)])
    assert gate.main(["--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["external_missing"] == ["src/x.php:1 A"]


def test_main_scan_runtime_error_exit_two(monkeypatch, capsys):
    def boom():
        raise RuntimeError("git ls-files 失败: fatal")
    monkeypatch.setattr(gate, "collect_symbols", boom)
    assert gate.main([]) == 2
    err = capsys.readouterr().err
    assert "docstring gate 配置/扫描面错误" in err and "fatal" in err


def test_main_oserror_exit_two(monkeypatch, capsys):
    def boom():
        raise OSError("No such file or directory: 'src/Gone.php'")
    monkeypatch.setattr(gate, "collect_symbols", boom)
    assert gate.main(["--json"]) == 2
    assert "docstring gate 配置/扫描面错误" in capsys.readouterr().err


def test_main_unknown_argument_exits(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_symbols", lambda: [])
    with pytest.raises(SystemExit) as excinfo:
        gate.main(["--nope"])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
