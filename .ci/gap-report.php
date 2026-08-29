<?php

declare(strict_types=1);

/**
 * 覆盖率缺口定位（临时诊断脚本）：列出行未覆盖与分支未覆盖的精确位置。
 * 用法：php .ci/gap-report.php  （先跑 --path-coverage 产出 coverage/xml + coverage/cov.php）
 */

// ---- 行缺口（coverage/xml）----
$lineGaps = [];
foreach (glob(__DIR__ . '/../coverage/xml/*.xml') ?: [] as $file) {
    $xml = @simplexml_load_file($file);
    if ($xml === false) {
        continue;
    }
    foreach ($xml->xpath('//file') as $fnode) {
        $name = (string) $fnode['name'];
        foreach ($fnode->line as $line) {
            if ((int) $line['count'] === 0 && in_array((string) $line['type'], ['stmt', 'method'], true)) {
                $lineGaps[$name][] = (int) $line['num'];
            }
        }
    }
}
echo "=== 行缺口 ===\n";
foreach ($lineGaps as $name => $lines) {
    echo $name, ': ', implode(',', $lines), "\n";
}

// ---- 分支缺口（cov.php 快照）----
$snapshot = __DIR__ . '/../coverage/cov.php';
if (!file_exists($snapshot) || !file_exists(__DIR__ . '/../vendor/autoload.php')) {
    exit(0);
}
require __DIR__ . '/../vendor/autoload.php';
/** @var \SebastianBergmann\CodeCoverage\CodeCoverage $cov */
$cov = require $snapshot;
$pccc = (new ReflectionProperty($cov, 'data'))->getValue($cov);
$fns = (new ReflectionProperty($pccc, 'functionCoverage'))->getValue($pccc);
echo "\n=== 分支缺口 ===\n";
foreach ($fns as $funcs) {
    foreach ($funcs as $fn => $info) {
        $branches = is_array($info) ? $info['branches'] : $info->branches;
        foreach ($branches as $idx => $brObj) {
            $br = is_array($brObj) ? $brObj : get_object_vars($brObj);
            if (($br['hit'] ?? []) !== []) {
                continue;
            }
            $start = $br['line_start'] ?? '?';
            $end = $br['line_end'] ?? '?';
            echo ($fn === '{main}' ? '(file)' : $fn), " 分支#$idx 行 $start-$end\n";
        }
    }
}
