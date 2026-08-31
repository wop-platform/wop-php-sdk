#!/usr/bin/env python3
"""等价清单锚点漂移检测（六仓统一模式，wop-php-sdk 实例）。

等价变异清单（tests/mutation/EQUIVALENT-MUTANTS.md）中的行号在源码演进后
会静默漂移——漂移后的「等价」主张不再指向原论证对象，等价剔除随之失效。
本脚本在每 PR 上校验：清单每条 (文件, 行, 锚前缀) 与当前源码一致。

用法: python3 scripts/check-equivalent-anchors.py
退出码: 0 = 全部锚点吻合；1 = 存在漂移（更新清单并重新论证后重跑）。
清单未含锚列（遗留条目）仅计数提示，不判失败——补锚后再收紧。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
LEDGER = ROOT / "tests" / "mutation" / "EQUIVALENT-MUTANTS.md"

ROW = re.compile(r"^\|\s*\d+\s*\|\s*`?([A-Za-z/]+\.php):(\d+)`?\s*\|([^|]*)\|([^|]*)\|\s*(.+?)\s*\|?\s*$")


def main() -> int:
    if not LEDGER.exists():
        print(f"清单缺失: {LEDGER}", file=sys.stderr)
        return 1
    drifted = []
    no_anchor = 0
    total = 0
    bad_rows = []
    for line in LEDGER.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        m = ROW.match(line)
        if not m:
            # 未解析行三分：注释（#/>）跳过；含 | 的表头/分隔线/无锚条目
            # 计入待补锚；其余（含 | 但非表格形态）判格式非法
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ">", "<!--")):
                continue
            if "|" in line:
                # 表头（含 #/位置/算子/锚/论证列名）与纯分隔线（---）跳过；
                # 其余 | 行视为无锚遗留条目（计入待补锚）
                if "位置" in line or re.match(r"^\|?[\s:|-]+\|?$", stripped):
                    continue
                no_anchor += 1
                print(f"[anchors] 无锚列条目（计入待补锚）: {stripped[:80]}",
                      file=sys.stderr)
            else:
                bad_rows.append(line)
            continue
        total += 1
        file, lineno, op, anchor, _proof = m.group(1), int(m.group(2)), m.group(3).strip(), m.group(4).strip(), m.group(5)
        anchor = anchor.strip("`")
        if not anchor or anchor in ("TODO", "—"):
            no_anchor += 1
            continue
        path = SRC / file
        if not path.exists():
            drifted.append(f"{file}:{lineno} 文件不存在（重命名/删除）")
            continue
        lines = path.read_text(encoding="utf-8").split("\n")
        if not 1 <= lineno <= len(lines):
            drifted.append(f"{file}:{lineno} 行号越界（源码 {len(lines)} 行）")
            continue
        actual = lines[lineno - 1].strip()
        if not actual.startswith(anchor):
            drifted.append(f"{file}:{lineno} 锚失配：清单={anchor!r} 实际={actual[:60]!r}")
    if bad_rows:
        for r in bad_rows:
            print(f"ANCHOR DRIFT: 台账格式非法: {r[:80]}", file=sys.stderr)
        return 1
    if drifted:
        for d in drifted:
            print(f"ANCHOR DRIFT: {d}", file=sys.stderr)
        return 1
    print(f"anchors ok ({total} 条，其中 {no_anchor} 条待补锚)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
