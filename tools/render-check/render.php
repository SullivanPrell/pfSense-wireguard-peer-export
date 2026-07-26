<?php
/*
 * render.php <page.php> — execute a WGX page against the stub environment
 * and dump {output, diagnostics} as JSON.
 *
 * Run one page per process so a fatal error or exit() cannot poison others.
 */

$page = $argv[1] ?? null;
if (!$page || !is_file($page)) {
    fwrite(STDERR, "usage: render.php <page.php>\n");
    exit(2);
}
// Must be absolute: the page is required AFTER chdir()ing into its directory,
// so a relative path would stop resolving the moment we move.
$page = realpath($page);

$stubs = __DIR__ . '/stubs';
set_include_path($stubs . PATH_SEPARATOR . get_include_path());

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '0');

$GLOBALS['__diags'] = [];
set_error_handler(function ($no, $str, $file, $line) {
    // Only diagnostics originating in the page under test matter; stub noise
    // is filtered by the caller comparing fork vs upstream anyway.
    $GLOBALS['__diags'][] = [
        'level' => $no, 'msg' => $str,
        'file'  => basename((string)$file), 'line' => $line,
    ];
    return true;
});

require_once $stubs . '/guiconfig.inc';

// ------------------------------------------------------------- fixture --
// A small but structurally complete config: one assigned tunnel, three peers
// in different states (active, expiring, expired) so list-render loops and
// their conditional branches all execute.
$GLOBALS['__cfg'] = [
    'system' => [
        'hostname' => 'fw', 'domain' => 'example.test',
        'webgui'   => ['protocol' => 'https', 'port' => '443'],
    ],
    'interfaces' => [
        'wan'  => ['if' => 'em0', 'descr' => 'WAN',   'ipaddr' => 'dhcp'],
        'lan'  => ['if' => 'em1', 'descr' => 'LAN',   'ipaddr' => '192.168.1.1', 'subnet' => '24'],
        'opt1' => ['if' => 'tun_wg0', 'descr' => 'WGWAN', 'ipaddr' => '10.6.0.1', 'subnet' => '24', 'enable' => true],
    ],
    'aliases' => ['alias' => []],
    'filter'  => ['rule'  => []],
    'installedpackages' => [
        'wireguard' => [
            'tunnels' => ['item' => [[
                'name' => 'tun_wg0', 'descr' => 'Road Warriors', 'enabled' => 'yes',
                'listenport' => '51820', 'mtu' => '1420',
                'publickey'  => 'kQF8mB0m2vJx7pT1cN9wY4hR6sL3aD5eG7iK9oQ2uW0=',
                'privatekey' => 'aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c=',
                'addresses'  => ['row' => [['address' => '10.6.0.1', 'mask' => '24']]],
            ]]],
            'peers' => ['item' => [
                [
                    'enabled' => 'yes', 'tun' => 'tun_wg0', 'descr' => 'laptop',
                    'publickey' => 'pK1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0=',
                    'presharedkey' => 'pS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0=',
                    'allowedips' => ['row' => [['address' => '10.6.0.10', 'mask' => '32']]],
                    'persistentkeepalive' => '25',
                    'wgx_expires' => (string)(time() + 86400 * 30),
                    'wgx_created' => (string)(time() - 86400 * 10),
                    'wgx_tier'    => 'admin',
                ],
                [
                    'enabled' => 'yes', 'tun' => 'tun_wg0', 'descr' => 'phone',
                    'publickey' => 'pK2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0=',
                    'allowedips' => ['row' => [['address' => '10.6.0.11', 'mask' => '32']]],
                    'wgx_expires' => (string)(time() + 3600),
                    'wgx_created' => (string)(time() - 86400 * 100),
                    'wgx_tier'    => 'user',
                ],
                [
                    'enabled' => 'no', 'tun' => 'tun_wg0', 'descr' => 'old-tablet',
                    'publickey' => 'pK3ccccccccccccccccccccccccccccccccccccccc0=',
                    'allowedips' => ['row' => [['address' => '10.6.0.12', 'mask' => '32']]],
                    'wgx_expires' => (string)(time() - 86400),
                    'wgx_created' => (string)(time() - 86400 * 200),
                    'wgx_tier'    => 'guest',
                ],
            ]],
        ],
        'wgexport' => ['config' => [[
            'sync_enable' => 'false', 'sync_ip' => '', 'sync_user' => 'admin',
            'sync_pass' => '', 'strict_tls' => 'true', 'enforce_psk' => 'false',
            'fallback_subnets' => '192.168.101.0/24', 'default_dns' => '8.8.8.8, 8.8.4.4',
            'default_ka' => '25', 'default_tier' => 'admin', 'key_rotation_days' => '90',
            'enable_geo' => 'false', 'quota_limit_gb' => '100', 'auto_cron' => 'true',
        ]]],
    ],
];

// ------------------------------------------------------------- request --
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_NAME']    = '/wgx/' . basename($page);
$_SERVER['PHP_SELF']       = $_SERVER['SCRIPT_NAME'];
$_SERVER['HTTP_HOST']      = 'fw.example.test';
$_SERVER['REMOTE_ADDR']    = '192.168.1.100';
$_SERVER['HTTPS']          = 'on';
$_GET = $_POST = $_REQUEST = [];
$_SESSION = ['Username' => 'admin'];

$fatal = null;
register_shutdown_function(function () use (&$fatal) {
    $e = error_get_last();
    $out = ob_get_level() ? ob_get_clean() : '';
    $payload = [
        'output' => $out,
        'diags'  => $GLOBALS['__diags'],
        'fatal'  => ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_COMPILE_ERROR, E_CORE_ERROR], true))
                    ? ['msg' => $e['message'], 'file' => basename($e['file']), 'line' => $e['line']]
                    : null,
    ];
    file_put_contents('php://stdout', json_encode($payload));
});

chdir(dirname($page));
ob_start();
require $page;
