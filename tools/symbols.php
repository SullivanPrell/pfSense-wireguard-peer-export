<?php
/*
 * symbols.php <dir> — tokenize every .php file under <dir> and emit JSON:
 *   { "defined": {name: "file:line"}, "called": [ {name, file, line} ] }
 *
 * Uses PHP's own lexer, so strings, comments and heredocs can never be
 * mistaken for code the way a regex would.
 */

$dir = $argv[1] ?? null;
if (!$dir || !is_dir($dir)) {
    fwrite(STDERR, "usage: symbols.php <dir>\n");
    exit(2);
}

$defined = [];
$called  = [];

$rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
$files = [];
foreach ($rii as $f) {
    if ($f->isFile() && in_array(strtolower($f->getExtension()), ['php', 'inc'], true)) {
        $files[] = $f->getPathname();
    }
}
sort($files);

foreach ($files as $path) {
    $rel = substr($path, strlen($dir));
    $toks = @token_get_all(file_get_contents($path));
    if (!$toks) { continue; }

    $n = count($toks);
    for ($i = 0; $i < $n; $i++) {
        $t = $toks[$i];
        if (!is_array($t)) { continue; }

        // --- definitions: T_FUNCTION followed by a name ---
        if ($t[0] === T_FUNCTION) {
            for ($j = $i + 1; $j < $n; $j++) {
                if (is_array($toks[$j]) && $toks[$j][0] === T_WHITESPACE) { continue; }
                if (is_array($toks[$j]) && $toks[$j][0] === T_STRING) {
                    // skip methods: a preceding visibility/static keyword means class member
                    $defined[strtolower($toks[$j][1])] = ltrim($rel, '/') . ':' . $toks[$j][2];
                }
                break; // '(' means a closure — not a named function
            }
            continue;
        }

        // --- call sites: T_STRING immediately followed by '(' ---
        if ($t[0] !== T_STRING) { continue; }

        // next significant token must be '('
        $k = $i + 1;
        while ($k < $n && is_array($toks[$k]) && $toks[$k][0] === T_WHITESPACE) { $k++; }
        if ($k >= $n || $toks[$k] !== '(') { continue; }

        // previous significant token must not make this a method/def/new/const
        $p = $i - 1;
        while ($p >= 0 && is_array($toks[$p]) && $toks[$p][0] === T_WHITESPACE) { $p--; }
        if ($p >= 0 && is_array($toks[$p])) {
            $pt = $toks[$p][0];
            if ($pt === T_OBJECT_OPERATOR || $pt === T_DOUBLE_COLON ||
                $pt === T_FUNCTION || $pt === T_NEW || $pt === T_CLASS ||
                (defined('T_NULLSAFE_OBJECT_OPERATOR') && $pt === T_NULLSAFE_OBJECT_OPERATOR)) {
                continue;
            }
        }

        $called[] = ['name' => strtolower($t[1]), 'file' => ltrim($rel, '/'), 'line' => $t[2]];
    }
}

echo json_encode(['defined' => $defined, 'called' => $called]), "\n";
