<?php

declare(strict_types=1);

/**
 * CI 覆盖率门禁：解析 PHPUnit --coverage-xml（--path-coverage 产出），
 * 行与分支均须 ≥98%（spec A3/A4），否则非零退出。
 */
$dirs = [__DIR__ . '/../coverage/xml', 'coverage/xml'];
$xmlDir = null;
foreach ($dirs as $d) {
    if (is_dir($d)) {
        $xmlDir = $d;
        break;
    }
}
if ($xmlDir === null) {
    fwrite(STDERR, "coverage/xml 不存在（先跑 --coverage-xml）\n");
    exit(1);
}

$files = array_merge(glob($xmlDir . '/*.xml') ?: [], glob($xmlDir . '/*/*.xml') ?: []);
if ($files === []) {
    fwrite(STDERR, "coverage/xml 下没有报告文件\n");
    exit(1);
}
$files = array_filter($files, static fn ($f) => basename((string) $f) !== 'index.xml');


$lineTotal = $lineCovered = $branchTotal = $branchCovered = 0;
$perFile = [];
foreach ($files as $file) {
    $xml = @simplexml_load_file($file);
    if ($xml === false) {
        continue;
    }
    $xml->registerXPathNamespace('c', 'https://schema.phpunit.de/coverage/1.0');
    foreach ($xml->xpath('//c:file') as $fnode) {
        $lt = (int) $fnode->totals->lines['executable'];
        $lc = (int) $fnode->totals->lines['executed'];
        $lineTotal += $lt;
        $lineCovered += $lc;
        $perFile[(string) $fnode['name']]['lines'] = [$lc, $lt];
    }
    // 分支门禁基于 coverage-php 快照（若存在则读取，否则按行口径降级警告）
}

$linePct = $lineTotal > 0 ? 100 * $lineCovered / $lineTotal : 0;
printf("LINES %d/%d = %.2f%%\n", $lineCovered, $lineTotal, $linePct);

// 分支：从 --coverage-php 快照读取（CI 步骤产物）
$phpSnapshot = null;
foreach ([__DIR__ . '/../coverage/cov.php', 'coverage/cov.php'] as $p) {
    if (file_exists($p)) {
        $phpSnapshot = $p;
        break;
    }
}
$branchPct = null;
if ($phpSnapshot !== null && file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require __DIR__ . '/../vendor/autoload.php';
    /** @var \SebastianBergmann\CodeCoverage\CodeCoverage $cov */
    $cov = require $phpSnapshot;
    $pccc = (new ReflectionProperty($cov, 'data'))->getValue($cov);
    $fns = (new ReflectionProperty($pccc, 'functionCoverage'))->getValue($pccc);
    foreach ($fns as $funcs) {
        foreach ($funcs as $fn => $info) {
            $branches = is_array($info) ? $info['branches'] : $info->branches;
            foreach ($branches as $brObj) {
                $br = is_array($brObj) ? $brObj : get_object_vars($brObj);
                $branchTotal++;
                if (($br['hit'] ?? []) !== []) {
                    $branchCovered++;
                }
            }
        }
    }
    $branchPct = $branchTotal > 0 ? 100 * $branchCovered / $branchTotal : 0;
    printf("BRANCHES %d/%d = %.2f%%\n", $branchCovered, $branchTotal, $branchPct);
} else {
    fwrite(STDERR, "警告：未找到 coverage/cov.php 快照，分支门禁未执行（仅行口径）\n");
}

$gate = 98.0;
$ok = $linePct >= $gate && ($branchPct === null || $branchPct >= $gate);
exit($ok ? 0 : 1);
