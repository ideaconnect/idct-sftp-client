#!/usr/bin/env php
<?php

declare(strict_types=1);

// Usage: php tests/bin/check-coverage.php <clover.xml> <min-percentage>
// Exits non-zero if line coverage is below the threshold.

if ($argc < 3) {
    fwrite(STDERR, "Usage: {$argv[0]} <clover.xml> <min-percentage>\n");
    exit(2);
}

$cloverPath = $argv[1];
$minPercent = (float) $argv[2];

if (! is_file($cloverPath)) {
    fwrite(STDERR, "Clover file not found: {$cloverPath}\n");
    exit(2);
}

$xml = simplexml_load_file($cloverPath);
if ($xml === false) {
    fwrite(STDERR, "Could not parse Clover XML: {$cloverPath}\n");
    exit(2);
}

$metrics = $xml->project->metrics ?? null;
if ($metrics === null) {
    fwrite(STDERR, "No <metrics> element in Clover XML.\n");
    exit(2);
}

$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
$percent = $statements === 0 ? 100.0 : ($covered / $statements) * 100;

printf("Line coverage: %.2f%% (%d/%d statements, threshold %.2f%%)\n", $percent, $covered, $statements, $minPercent);

if ($percent + 0.0001 < $minPercent) {
    fwrite(STDERR, "Coverage below threshold.\n");
    exit(1);
}

exit(0);
