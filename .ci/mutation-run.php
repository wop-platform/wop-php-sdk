<?php

declare(strict_types=1);

/**
 * 变异测试驱动（测试基础设施，不改 src 语义——跑完即恢复并校验 hash）。
 *
 * token 级变异算子 13 类（覆盖条件边界/等值取反/逻辑连接词/算术/位运算/
 * 整数常量/布尔字面量/字符串字面量/一元取反删除）：
 *   rel-lt  `<`→`<=`      rel-gt  `>`→`>=`      rel-lte `<=`→`<`      rel-gte `>=`→`>`
 *   eq-neg  `===`→`!==`  neq-neg `!==`→`===`   eq2-neg `==`→`!=`    neq2-neg `!=`→`==`
 *   logic   `&&`↔`||`    arith+  `+`→`-`       arith-  `-`→`+`（二元）
 *   bit-xor `^`→`|`      int+1   n→n+1         int-0   n→0
 *   bool    true↔false   str-empty ''          not-del `!x`→`x`
 *
 * 评分：phpunit 退出非 0 或超时 → KILLED；退出 0 → SURVIVED；
 *       变异体语法破坏（phpunit 无法运行）→ INVALID（排除出分母）。
 * 用法：php .ci/mutation-run.php [--filter=op[,op...]] [--suite-args="..."]
 */

const REPO = __DIR__ . '/..';
const PHPUNIT_TIMEOUT = 60;

/** @param list<string> $files */
function srcFiles(): array
{
    $files = [];
    $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(REPO . '/src', FilesystemIterator::SKIP_DOTS));
    foreach ($iter as $f) {
        if ($f->isFile() && $f->getExtension() === 'php') {
            $files[] = $f->getPathname();
        }
    }
    sort($files);
    return $files;
}

/** 恢复全部 src 快照（信号/fatal/异常路径兜底，幂等：仅写回与快照不一致的文件）。 */
function restoreSnapshot(array $snapshot): void
{
    foreach ($snapshot as $f => $code) {
        if (@file_get_contents($f) !== $code) {
            file_put_contents($f, $code);
            fwrite(STDERR, "已恢复被中断残留的变异文件: $f\n");
        }
    }
}

final class Mutant
{
    public function __construct(
        public readonly string $file,
        public readonly int $tokenIndex,
        public readonly string $op,
        public readonly int $line,
        public readonly string $original,
        public readonly string $replacement,
    ) {
    }
}

/** token 级安全重组：仅替换目标 token 文本，其余逐字保留。 */
function mutateToken(string $code, int $targetIndex, string $replacement): ?string
{
    $tokens = PhpToken::tokenize($code);
    if (!isset($tokens[$targetIndex])) {
        return null;
    }
    $out = '';
    foreach ($tokens as $i => $t) {
        $out .= $i === $targetIndex ? $replacement : $t->text;
    }
    return $out;
}

/** 前一个有意义的 token（跳过空白/注释）。 */
function prevMeaningful(array $tokens, int $i): ?PhpToken
{
    for ($j = $i - 1; $j >= 0; $j--) {
        $id = $tokens[$j]->id;
        if ($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT) {
            continue;
        }
        return $tokens[$j];
    }
    return null;
}

/** 二元 `+`/`-` 判定：前一 token 为操作数结尾。 */
function isBinaryOperandEnd(?PhpToken $prev): bool
{
    if ($prev === null) {
        return false;
    }
    return $prev->is([T_VARIABLE, T_STRING, T_LNUMBER, T_DNUMBER, T_CONSTANT_ENCAPSED_STRING])
        || $prev->text === ')' || $prev->text === ']';
}

/** `!` 判定：前一 token 非操作数结尾（否则是 `!=`/`!==` 已是独立 token，不会到这；双保险）。 */
function isUnaryNot(?PhpToken $prev): bool
{
    return $prev !== null && !isBinaryOperandEnd($prev) && $prev->text !== ']' && $prev->text !== ')';
}

/** @return list<Mutant> */
function collectMutants(string $file, string $code): array
{
    $tokens = PhpToken::tokenize($code);
    // 类声明起点：此行之前的 token（declare/namespace/use）不变异
    $classLine = PHP_INT_MAX;
    foreach ($tokens as $t) {
        if ($t->is(T_CLASS)) {
            $classLine = $t->line;
            break;
        }
    }
    $mutants = [];
    $add = function (int $i, string $op, string $orig, string $repl) use ($file, $tokens, &$mutants, $classLine): void {
        if ($tokens[$i]->line >= $classLine) {
            $mutants[] = $tokens[$i]->line . '|' . $op; // 占位，最终在主循环物化
        }
    };
    // 为可读报告直接物化（不走闭包占位）
    $mutants = [];
    foreach ($tokens as $i => $t) {
        if ($t->line < $classLine) {
            continue;
        }
        $prev = prevMeaningful($tokens, $i);
        $text = $t->text;
        $push = function (string $op, string $repl) use ($file, $i, $t, $text, &$mutants): void {
            $mutants[] = [$file, $i, $op, $t->line, $text, $repl];
        };
        // —— 关系/等值/逻辑（命名 token）——
        if ($t->is(T_IS_SMALLER_OR_EQUAL)) { $push('rel-lte', '<'); continue; }
        if ($t->is(T_IS_GREATER_OR_EQUAL)) { $push('rel-gte', '>'); continue; }
        if ($t->is(T_IS_IDENTICAL))        { $push('eq-neg', '!=='); continue; }
        if ($t->is(T_IS_NOT_IDENTICAL))    { $push('neq-neg', '==='); continue; }
        if ($t->is(T_IS_EQUAL))            { $push('eq2-neg', '!='); continue; }
        if ($t->is(T_IS_NOT_EQUAL))        { $push('neq2-neg', '=='); continue; }
        if ($t->is(T_BOOLEAN_AND))         { $push('logic', '||'); continue; }
        if ($t->is(T_BOOLEAN_OR))          { $push('logic', '&&'); continue; }
        // —— 单字符操作符 ——
        if ($t->id === ord('<')) { $push('rel-lt', '<='); continue; }
        if ($t->id === ord('>')) { $push('rel-gt', '>='); continue; }
        if ($t->id === ord('^')) { $push('bit-xor', '|'); continue; }
        if ($t->id === ord('+') && isBinaryOperandEnd($prev)) { $push('arith-plus', '-'); continue; }
        if ($t->id === ord('-') && isBinaryOperandEnd($prev)) { $push('arith-minus', '+'); continue; }
        if ($t->id === ord('!') && isUnaryNot($prev))         { $push('not-del', ''); continue; }
        // —— 字面量 ——
        if ($t->is(T_LNUMBER)) {
            if ($text !== '0') {
                $push('int-plus1', (string) ((int) $text + 1));
                $push('int-zero', '0');
            }
            continue;
        }
        if ($t->is([T_CONSTANT_ENCAPSED_STRING])) {
            $inner = substr($text, 1, -1);
            if ($inner !== '' && $text[0] === "'") { // 仅单引号（无插值/转义歧义）
                $push('str-empty', "''");
            }
            continue;
        }
        if ($t->is(T_STRING) && ($text === 'true' || $text === 'false')) {
            $isAccess = $prev !== null && ($prev->text === '->' || $prev->text === '::' || $prev->is(T_FUNCTION) || $prev->is(T_FN));
            if (!$isAccess) {
                $push('bool-flip', $text === 'true' ? 'false' : 'true');
            }
        }
    }
    return array_map(
        static fn (array $m): Mutant => new Mutant($m[0], $m[1], $m[2], $m[3], $m[4], $m[5]),
        $mutants,
    );
}

/** 跑全量套件，返回 [exitCode, output, timedOut]。 */
function runSuite(string $extraArgs = ''): array
{
    $cmd = 'cd ' . escapeshellarg(REPO) . ' && vendor/bin/phpunit --no-progress --stop-on-failure ' . $extraArgs . ' 2>&1';
    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        return [-1, 'proc_open failed', false];
    }
    stream_set_blocking($pipes[1], false);
    $out = '';
    $start = microtime(true);
    $timedOut = false;
    while (true) {
        $chunk = fread($pipes[1], 65536);
        if (is_string($chunk) && $chunk !== '') {
            $out .= $chunk;
        }
        $status = proc_get_status($proc);
        if (!$status['running']) {
            break;
        }
        if (microtime(true) - $start > PHPUNIT_TIMEOUT) {
            $timedOut = true;
            proc_terminate($proc, 9);
            // 给回收留时间
            usleep(200000);
            break;
        }
        usleep(20000);
    }
    // running 下 break 时可能还没退出，读余量
    $status = proc_get_status($proc);
    $exit = $timedOut ? 124 : ($status['running'] ? -1 : $status['exitcode']);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    return [$exit, $out, $timedOut];
}

// ==================== 主流程 ====================
$optFilter = '';
for ($k = 1; $k < $argc; $k++) {
    if (str_starts_with($argv[$k], '--filter=')) {
        $optFilter = substr($argv[$k], 9);
    }
}
$allowOps = $optFilter === '' ? null : explode(',', $optFilter);

$files = srcFiles();
$snapshot = [];
foreach ($files as $f) {
    $snapshot[$f] = (string) file_get_contents($f);
}

// 中断兜底：脚本被信号打断或 fatal 时恢复 src，避免残留变异体污染后续基线。
// 正常路径仍由主循环逐体恢复并做终局校验（restoreSnapshot 幂等，重复调用无副作用）。
register_shutdown_function(restoreSnapshot(...), $snapshot);
if (extension_loaded('pcntl')) {
    pcntl_async_signals(true);
    $onSignal = static function (int $sig) use ($snapshot): void {
        restoreSnapshot($snapshot);
        fwrite(STDERR, "收到信号 {$sig}，已恢复 src 快照，终止\n");
        exit(128 + $sig);
    };
    pcntl_signal(SIGINT, $onSignal);
    pcntl_signal(SIGTERM, $onSignal);
}

// 预检：基线必须绿
echo "预检基线套件...\n";
[$exit, $out] = runSuite();
if ($exit !== 0) {
    fwrite(STDERR, "基线 phpunit 非绿（exit=$exit），终止：\n" . substr($out, -2000) . "\n");
    exit(1);
}
echo "基线绿\n";

// 收集
$all = [];
foreach ($files as $f) {
    foreach (collectMutants($f, $snapshot[$f]) as $m) {
        if ($allowOps !== null && !in_array($m->op, $allowOps, true)) {
            continue;
        }
        $all[] = $m;
    }
}
$total = count($all);
echo "变异点总数: {$total}（文件 " . count($files) . " 个）\n";

$results = [];
$idx = 0;
try {
    foreach ($all as $m) {
        $idx++;
        $mutated = mutateToken($snapshot[$m->file], $m->tokenIndex, $m->replacement);
        if ($mutated === null) {
            $results[] = [$m, 'INVALID', 'token 失配'];
            continue;
        }
        file_put_contents($m->file, $mutated);
        [$exit, $out, $timedOut] = runSuite();
        if ($timedOut) {
            $verdict = 'KILLED';
            $note = 'timeout';
        } elseif ($exit === 0) {
            $verdict = 'SURVIVED';
            $note = '';
        } elseif (str_contains($out, 'Parse error') || str_contains($out, 'syntax error') || str_contains($out, 'PHP Fatal error') && str_contains($out, 'Cannot redeclare') === false && str_contains($out, 'bootstrap')) {
            // 语法破坏 = INVALID（不计数）。PHP Fatal 仅在 phpunit 启动阶段才视为 invalid；
            // 测试运行期 fatal（变异引发运行时崩溃）算 KILLED，由 exit!=0 且非 parse 判定。
            $verdict = str_contains($out, 'Parse error') || str_contains($out, 'syntax error') ? 'INVALID' : 'KILLED';
            $note = 'fatal';
        } else {
            $verdict = 'KILLED';
            $note = 'exit=' . $exit;
        }
        // 恢复
        file_put_contents($m->file, $snapshot[$m->file]);
        $results[] = [$m, $verdict, $note];
        if ($idx % 25 === 0) {
            $killed = count(array_filter($results, static fn ($r) => $r[1] === 'KILLED'));
            echo "进度 $idx/$total（killed {$killed}）\n";
        }
    }
} finally {
    // 循环中途抛异常时兜底恢复（信号/fatal 由上面注册的 handler 与 shutdown 覆盖）
    restoreSnapshot($snapshot);
}

// 复原校验
foreach ($files as $f) {
    if ((string) file_get_contents($f) !== $snapshot[$f]) {
        fwrite(STDERR, "严重：$f 恢复失败\n");
        exit(1);
    }
}
[$exit] = runSuite();
echo $exit === 0 ? "src 已恢复且套件回绿\n" : "警告：恢复后基线异常 exit=$exit\n";

// ==================== 报告 ====================
$byOp = [];
foreach ($results as [$m, $verdict]) {
    $byOp[$m->op][$verdict] = ($byOp[$m->op][$verdict] ?? 0) + 1;
}
ksort($byOp);

$sumKilled = $sumSurvived = $sumInvalid = 0;
foreach ($results as [, $verdict]) {
    if ($verdict === 'KILLED') {
        $sumKilled++;
    } elseif ($verdict === 'SURVIVED') {
        $sumSurvived++;
    } else {
        $sumInvalid++;
    }
}
$denom = $sumKilled + $sumSurvived;
$msi = $denom > 0 ? 100 * $sumKilled / $denom : 0.0;

$lines = [];
$lines[] = '# wop-php-sdk 变异测试报告';
$lines[] = '';
$lines[] = '- 分母口径：KILLED + SURVIVED（INVALID 语法破坏排除）';
$lines[] = sprintf('- 总变异体：%d（killed %d / survived %d / invalid %d）', count($results), $sumKilled, $sumSurvived, $sumInvalid);
$lines[] = sprintf('- **击杀率 MSI = %.2f%%**（%d/%d）', $msi, $sumKilled, $denom);
$lines[] = '';
$lines[] = '| 算子 | 变异 | killed | survived | invalid | 击杀率 |';
$lines[] = '|---|---|---|---|---|---|';
$opDesc = [
    'rel-lt' => '`<`→`<=`', 'rel-gt' => '`>`→`>=`', 'rel-lte' => '`<=`→`<`', 'rel-gte' => '`>=`→`>`',
    'eq-neg' => '`===`→`!==`', 'neq-neg' => '`!==`→`===`', 'eq2-neg' => '`==`→`!=`', 'neq2-neg' => '`!=`→`==`',
    'logic' => '`&&`↔`||`', 'arith-plus' => '`+`→`-`', 'arith-minus' => '`-`→`+`', 'bit-xor' => '`^`→`|`',
    'int-plus1' => '整数 n→n+1', 'int-zero' => '整数 n→0', 'bool-flip' => 'true↔false',
    'str-empty' => "字符串→`''`", 'not-del' => '`!x`→`x`',
];
foreach ($byOp as $op => $counts) {
    $k = $counts['KILLED'] ?? 0;
    $s = $counts['SURVIVED'] ?? 0;
    $inv = $counts['INVALID'] ?? 0;
    $d = $k + $s;
    $lines[] = sprintf('| %s | %s | %d | %d | %d | %s |', $op, $opDesc[$op] ?? '?', $k, $s, $inv, $d > 0 ? sprintf('%.1f%%', 100 * $k / $d) : '-');
}
$survivors = array_filter($results, static fn ($r) => $r[1] === 'SURVIVED');
if ($survivors !== []) {
    $lines[] = '';
    $lines[] = '## 存活变异体（survived，人工复核等价性）';
    foreach ($survivors as [$m]) {
        $rel = str_replace(REPO . '/', '', $m->file);
        $lines[] = sprintf('- `%s:%d` %s：`%s` → `%s`', $rel, $m->line, $m->op, $m->original, $m->replacement);
    }
}
$report = implode("\n", $lines) . "\n";
file_put_contents(REPO . '/docs/mutation-report.md', $report);
file_put_contents(REPO . '/docs/mutation-results.json', json_encode(
    array_map(static fn ($r) => [
        'file' => str_replace(REPO . '/', '', $r[0]->file), 'line' => $r[0]->line, 'op' => $r[0]->op,
        'original' => $r[0]->original, 'replacement' => $r[0]->replacement, 'verdict' => $r[1], 'note' => $r[2],
    ], $results),
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
));
echo "\n" . $report;
echo "报告: docs/mutation-report.md\n";
exit($msi >= 90.0 ? 0 : 1);
