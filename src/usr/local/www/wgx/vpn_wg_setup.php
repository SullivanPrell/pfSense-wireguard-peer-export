<?php
/*
 * vpn_wg_setup.php
 *
 * WG Suite - WireGuard Provisioning Package for pfSense
 * Copyright (c) 2026 3um3le3ee <3um3le3ee@mail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// === 6.A. Initialization & Dependency Loading ===
require_once("guiconfig.inc");
require_once("functions.inc");
require_once("filter.inc");
require_once("pkg-utils.inc");
require_once("util.inc");

// Audit log helper — mirrors wgx_audit_log() in vpn_wg_export.php
if (!function_exists('wgx_audit_log')) {
    function wgx_audit_log(string $msg): void
    {
        $log_file = '/var/db/wgx_audit.log';
        if (file_exists($log_file) && filesize($log_file) > 5242880) {
            rename($log_file, $log_file . '.1');
        }
        $user = !empty($_SESSION["Username"]) ? $_SESSION["Username"]
        : (!empty($_SESSION["authinfo"]["username"]) ? $_SESSION["authinfo"]["username"] : "System");
        $line = date('Y-m-d H:i:s') . ' [WG Suite] ' . $user . ' - ' . $msg . "\n";
        file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
    }
}

$local_interfaces = get_configured_interface_with_descr();
$lan_ip           = config_get_path('interfaces/lan/ipaddr', 'Unknown');
$lan_subnet       = config_get_path('interfaces/lan/subnet', '24');

// === 6.A.-1. Deploy progress streaming (Server-Sent Events) ===
// The frontend intercepts form submit and POSTs with header
//   X-WGX-Stream: 1
// If we detect that header, we switch the response into text/event-stream
// and emit progress events after each stage of the deploy so the overlay
// UI can show a live "software-installer" style step list. Without the
// header, all wgx_stream_* calls no-op and the flow is exactly as before.

if (!isset($GLOBALS['wgx_stream_mode'])) {
    $GLOBALS['wgx_stream_mode'] = false;
}

if (!function_exists('wgx_stream_begin')) {
    function wgx_stream_begin(): void
    {
        if ($GLOBALS['wgx_stream_mode']) { return; }
        // Only stream when the frontend explicitly asked for it. This keeps
        // the plain POST-Redirect-Get path intact for JS-off / fallback.
        if (($_SERVER['HTTP_X_WGX_STREAM'] ?? '') !== '1') { return; }
        $GLOBALS['wgx_stream_mode'] = true;
        @ini_set('output_buffering',        'off');
        @ini_set('zlib.output_compression', '0');
        @ini_set('implicit_flush',          '1');
        while (@ob_end_clean()) { /* drain */ }
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('X-Accel-Buffering: no');  // nginx: don't buffer this response
        header('Connection: keep-alive');
        // Two-KB comment padding so mid-boxes (proxies, gzip filters) flush
        // the response header block immediately instead of waiting for a
        // full buffer's worth of body.
        echo ':' . str_repeat(' ', 2048) . "\n\n";
        @ob_implicit_flush(true);
        @flush();
    }
}

if (!function_exists('wgx_stream_event')) {
    function wgx_stream_event(string $event, array $data = []): void
    {
        if (!$GLOBALS['wgx_stream_mode']) { return; }
        $payload = json_encode(['event' => $event] + $data);
        if ($payload === false) { return; }
        echo 'data: ' . $payload . "\n\n";
        @flush();
    }
}

if (!function_exists('wgx_step_start')) {
    function wgx_step_start(string $id, string $label): void
    {
        wgx_stream_event('step_start', ['id' => $id, 'label' => $label]);
    }
}

if (!function_exists('wgx_step_done')) {
    function wgx_step_done(string $id, string $detail = ''): void
    {
        wgx_stream_event('step_done', ['id' => $id, 'detail' => $detail]);
    }
}

if (!function_exists('wgx_step_fail')) {
    function wgx_step_fail(string $id, string $detail = ''): void
    {
        wgx_stream_event('step_fail', ['id' => $id, 'detail' => $detail]);
    }
}

// === 6.A.0. WireGuard binary probe + sodium keygen fallback ===
// Some pfSense Plus 25.11 / 26.03 builds ship a wrapper `wg` at a base
// path that is NOT wireguard-tools — it answers "Config file not specified"
// instead of a key. Trusting is_executable() alone lets that broken binary
// win. wgx_setup_find_wg_bin() probes each candidate with a live `genkey`
// call and only accepts binaries that produce a valid 44-char base64 key,
// preferring the official WireGuard package binary. When no candidate
// works, wgx_setup_gen_keypair() falls back to a pure-PHP sodium keypair —
// a WireGuard private key is 32 clamped random bytes and the public key is
// X25519 scalarmult_base, byte-identical to `wg pubkey`.

if (!function_exists('wgx_setup_key_valid')) {
    function wgx_setup_key_valid($key): bool
    {
        return is_string($key) && preg_match('/^[A-Za-z0-9+\/]{43}=$/', trim($key)) === 1;
    }
}

if (!function_exists('wgx_setup_wg_run')) {
    function wgx_setup_wg_run(string $bin, string $sub, string $stdin = ''): string
    {
        $desc  = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc  = @proc_open(escapeshellarg($bin) . ' ' . escapeshellarg($sub), $desc, $pipes);
        if (!is_resource($proc)) {
            return '';
        }
        if ($stdin !== '') { fwrite($pipes[0], $stdin); }
        fclose($pipes[0]);
        $out = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);
        return trim((string)$out);
    }
}

if (!function_exists('wgx_setup_find_wg_bin')) {
    function wgx_setup_find_wg_bin(): string
    {
        foreach (['/usr/local/bin/wg', '/usr/bin/wg', '/sbin/wg', '/usr/sbin/wg'] as $candidate) {
            if (!is_executable($candidate)) { continue; }
            if (wgx_setup_key_valid(wgx_setup_wg_run($candidate, 'genkey'))) {
                return $candidate;
            }
        }
        return '';
    }
}

if (!function_exists('wgx_setup_gen_keypair')) {
    function wgx_setup_gen_keypair(): array
    {
        $wg_bin = wgx_setup_find_wg_bin();
        if ($wg_bin !== '') {
            $priv = wgx_setup_wg_run($wg_bin, 'genkey');
            if (wgx_setup_key_valid($priv)) {
                $pub = wgx_setup_wg_run($wg_bin, 'pubkey', $priv . "\n");
                if (wgx_setup_key_valid($pub)) {
                    return ['priv' => $priv, 'pub' => $pub, 'source' => 'wg-binary'];
                }
            }
        }
        // Sodium fallback — WireGuard keys are Curve25519/X25519.
        if (function_exists('sodium_crypto_scalarmult_base')) {
            $raw = random_bytes(32);
            $raw[0]  = chr(ord($raw[0]) & 248);
            $raw[31] = chr((ord($raw[31]) & 127) | 64);
            $priv = base64_encode($raw);
            $pub  = base64_encode(sodium_crypto_scalarmult_base($raw));
            if (wgx_setup_key_valid($priv) && wgx_setup_key_valid($pub)) {
                return ['priv' => $priv, 'pub' => $pub, 'source' => 'sodium'];
            }
        }
        return ['priv' => '', 'pub' => '', 'source' => 'failed'];
    }
}

// === 6.A.1. Auto-Detect Next Available Tunnel Parameters ===
$next_port = 51820;
$next_v4   = "10.10.10.1/24";
$next_v6   = "";
$used_ports = [];
$used_v4    = [];
$used_v6    = [];

$tunnel_items = config_get_path('installedpackages/wireguard/tunnels/item', []);
foreach ($tunnel_items as $tun) {
    if (!empty($tun['listenport'])) {
        $used_ports[] = (int)$tun['listenport'];
    }
    $addrs = $tun['addresses']['row'] ?? ($tun['addresses']['item'] ?? []);
    if (is_array($addrs)) {
        $rows = isset($addrs['address']) ? [$addrs] : $addrs;
        foreach ($rows as $a) {
            if (is_array($a) && !empty($a['address'])) {
                if (is_ipaddrv4($a['address'])) {
                    $used_v4[] = $a['address'];
                }
                if (is_ipaddrv6($a['address'])) {
                    $used_v6[] = $a['address'];
                }
            }
        }
    }
}

if (!empty($used_ports)) {
    $max_port = max($used_ports);
    if ($max_port >= 51820) {
        $next_port = $max_port + 1;
    }
}

if (!empty($used_v4)) {
    $last_v4 = end($used_v4);
    $parts   = explode('.', $last_v4);
    if (count($parts) === 4) {
        for ($i = 1; $i <= 25; $i++) {
            $third     = ((int)$parts[2] + ($i * 10)) % 256;
            $candidate = "{$parts[0]}.{$parts[1]}.{$third}.1";
            $conflict  = false;
            foreach ($used_v4 as $u) {
                if (strpos($u, "{$parts[0]}.{$parts[1]}.{$third}.") === 0) {
                    $conflict = true;
                    break;
                }
            }
            if (!$conflict) {
                $next_v4 = "{$candidate}/24";
                break;
            }
        }
    }
}

if (!empty($used_v6)) {
    $last_v6 = end($used_v6);
    $bin     = inet_pton($last_v6);
    if ($bin !== false) {
        $val    = (ord($bin[6]) << 8) + ord($bin[7]);
        $val    = ($val + 1) & 0xFFFF;
        $bin[6] = chr($val >> 8);
        $bin[7] = chr($val & 0xFF);
        $next_v6 = inet_ntop($bin) . '/64';
    }
}

// === 6.B.0 WebSocket Server Auto-Deploy ===

/**
 * Deploys the WebSocket-to-WireGuard bridge server on this pfSense box.
 * Called automatically when a tunnel is created with WebSocket transport enabled.
 * Returns an array of ['ok'=>bool, 'msg'=>string] status messages.
 */
function wgx_deploy_ws_server(int $wg_port, int $new_webui_port, string $tun_iface = ''): array
{
    $steps = [];
    $tunnel_dir  = '/usr/local/www/wgx/tunnel';
    $server_file = "{$tunnel_dir}/wg_ws_server.php";
    $rc_file     = '/usr/local/etc/rc.d/wg_ws_server';
    $cert_dir    = '/usr/local/etc/wg_ws';
    $cert_pem    = $cert_dir . '/server.pem';
    $log_file    = '/var/log/wg_ws_server.log';

    // Ensure the cert directory exists with tight permissions
    if (!is_dir($cert_dir)) {
        mkdir($cert_dir, 0700, true);
    }

    // ----------------------------------------------------------------
    // Step 1: Export the current web UI cert to a PEM file
    // ----------------------------------------------------------------
    $step = ['label' => 'Export TLS certificate'];
    try {
        global $config;
        $ref  = $config['system']['webgui']['ssl-certref'] ?? '';
        $cert = $ref ? lookup_cert($ref) : null;
        if ($cert && !empty($cert['crt']) && !empty($cert['prv'])) {
            $pem = base64_decode($cert['crt']) . base64_decode($cert['prv']);
            file_put_contents($cert_pem, $pem);
            chmod($cert_pem, 0600);
            $step['ok']  = true;
            $step['msg'] = "Certificate exported to {$cert_pem}";
        } else {
            // No custom cert — generate a self-signed one via openssl
            $subj = '/C=US/ST=Local/L=Local/O=WGSuite/CN=pfSense-WGX';
            $cmd  = 'openssl req -x509 -newkey rsa:4096'
                  . ' -keyout ' . escapeshellarg($cert_pem)
                  . ' -out '    . escapeshellarg($cert_pem)
                  . ' -days 3650 -nodes'
                  . ' -subj '   . escapeshellarg($subj)
                  . ' 2>/dev/null';
            exec($cmd);
            chmod($cert_pem, 0600);
            $step['ok']  = file_exists($cert_pem);
            $step['msg'] = $step['ok']
            ? "Self-signed certificate generated at {$cert_pem}"
            : "Could not generate certificate — install openssl or add a cert in System > Cert Manager";
        }
    } catch (\Throwable $e) {
        $step['ok']  = false;
        $step['msg'] = 'Certificate export failed: ' . $e->getMessage();
    }
    $steps[] = $step;
    if (!$step['ok']) return $steps;

    // ----------------------------------------------------------------
    // Step 2: Move the web UI off port 443 (if it is still on 443)
    // ----------------------------------------------------------------
    $step = ['label' => 'Move web UI off port 443'];
    $current_port = (int)($config['system']['webgui']['port'] ?? 443);
    if ($current_port === 443 || $current_port === 0) {
        config_set_path('system/webgui/port', (string)$new_webui_port);
        // Do NOT restart the web UI here — the on-disk config still has
        // the OLD port (write_config runs later) so restarting now would
        // just re-bind the old port and lose the change. The caller flushes
        // the HTTP response first, then write_configs and restarts webgui
        // in a shutdown handler so the client never sees the disconnect.
        $GLOBALS['wgx_webgui_restart_needed'] = true;
        $GLOBALS['wgx_new_webui_port']        = (int)$new_webui_port;
        $step['ok']  = true;
        $step['msg'] = "Web UI moved to port {$new_webui_port}. "
        . "Access pfSense at https://&lt;ip&gt;:{$new_webui_port} after this.";
    } else {
        $step['ok']  = true;
        $step['msg'] = "Web UI is already on port {$current_port} — no change needed.";
    }
    $steps[] = $step;

    // ----------------------------------------------------------------
    // Step 3: Ensure server PHP file is in place
    // ----------------------------------------------------------------
    $step = ['label' => 'Verify server file'];
    if (!file_exists($server_file)) {
        $step['ok']  = false;
        $step['msg'] = "Server file not found at {$server_file}. "
        . "Ensure the package was installed correctly (pkg add).";
    } else {
        $step['ok']  = true;
        $step['msg'] = "Server file confirmed at {$server_file}";
    }
    $steps[] = $step;
    if (!$step['ok']) return $steps;

    // ----------------------------------------------------------------
    // Step 4: Install rc.d script
    // ----------------------------------------------------------------
    $step = ['label' => 'Install rc.d startup script'];
    $rc_src = "{$tunnel_dir}/wg_ws_server_rc.sh";
    if (file_exists($rc_src)) {
        copy($rc_src, $rc_file);
        chmod($rc_file, 0755);
        // Write config to /etc/rc.conf.local so it survives reboots
        $rc_conf = '/etc/rc.conf.local';
        $current = file_exists($rc_conf) ? file_get_contents($rc_conf) : '';
        // Always rewrite to ensure cert path and ports are correct
        $rc_new = preg_replace('/\n?wg_ws_server_[^\n]+/m', '', $current);
        $rc_content = rtrim($rc_new) . "\n"
            . "wg_ws_server_enable=\"YES\"\n"
            . "wg_ws_server_cert=\"{$cert_pem}\"\n"
            . "wg_ws_server_wg_port=\"{$wg_port}\"\n"
            . "wg_ws_server_port=\"443\"\n"
            . "wg_ws_server_path=\"/tunnel\"\n";
        file_put_contents($rc_conf, $rc_content, LOCK_EX);
        // Verify the write succeeded
        $verify = file_exists($rc_conf) ? file_get_contents($rc_conf) : '';
        $write_ok = strpos($verify, 'wg_ws_server_enable="YES"') !== false;
        $step['ok']  = $write_ok;
        $step['msg'] = $write_ok
            ? "rc.d script installed at {$rc_file} — enabled at boot via /etc/rc.conf.local"
            : "rc.d script installed but could not write /etc/rc.conf.local — run: echo 'wg_ws_server_enable=\"YES\"' >> /etc/rc.conf.local";
    } else {
        // rc.d script missing from package — write the full production version inline
        $inline_rc = <<<'SH'
#!/bin/sh
# PROVIDE: wg_ws_server
# REQUIRE: wireguard LOGIN
# KEYWORD: shutdown
. /etc/rc.subr
name="wg_ws_server"
rcvar="${name}_enable"
: ${wg_ws_server_enable:="NO"}
: ${wg_ws_server_cert:="/usr/local/etc/wg_ws/server.pem"}
: ${wg_ws_server_port:="443"}
: ${wg_ws_server_path:="/tunnel"}
: ${wg_ws_server_wg_port:="51820"}
: ${wg_ws_server_log:="/var/log/wg_ws_server.log"}
command="/usr/local/bin/php"
command_args="/usr/local/www/wgx/tunnel/wg_ws_server.php"
pidfile="/var/run/${name}.pid"
start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"
wg_ws_server_start() {
    if [ -f "${pidfile}" ] && kill -0 $(cat "${pidfile}") 2>/dev/null; then
        echo "${name} is already running."; return 1; fi
    if [ ! -f "${wg_ws_server_cert}" ]; then
        echo "ERROR: Certificate not found: ${wg_ws_server_cert}"; return 1; fi
    echo "Starting ${name}..."
    export WG_WS_CERT="${wg_ws_server_cert}"
    export WG_WS_PORT="${wg_ws_server_port}"
    export WG_WS_PATH="${wg_ws_server_path}"
    export WG_WG_PORT="${wg_ws_server_wg_port}"
    /usr/local/bin/php ${command_args} >> "${wg_ws_server_log}" 2>&1 &
    echo $! > "${pidfile}"
    echo "${name} started (pid $(cat ${pidfile}))"
}
wg_ws_server_stop() {
    if [ ! -f "${pidfile}" ]; then echo "${name} is not running."; return 0; fi
    pid=$(cat "${pidfile}")
    if ! kill -0 "${pid}" 2>/dev/null; then rm -f "${pidfile}"; return 0; fi
    echo "Stopping ${name} (pid ${pid})..."
    kill -TERM "${pid}"
    i=0; while kill -0 "${pid}" 2>/dev/null && [ $i -lt 10 ]; do sleep 0.5; i=$((i+1)); done
    kill -0 "${pid}" 2>/dev/null && kill -KILL "${pid}"
    rm -f "${pidfile}"; echo "${name} stopped."
}
wg_ws_server_status() {
    if [ -f "${pidfile}" ] && kill -0 $(cat "${pidfile}") 2>/dev/null; then
        echo "${name} is running (pid $(cat ${pidfile}))."
        echo "Last 5 log lines:"; tail -5 "${wg_ws_server_log}" 2>/dev/null
    else echo "${name} is NOT running."; fi
}
load_rc_config $name
run_rc_command "$1"
SH;
        file_put_contents($rc_file, $inline_rc);
        chmod($rc_file, 0755);
        // Also write rc.conf.local for this path
        $rc_conf2 = '/etc/rc.conf.local';
        $cur2 = file_exists($rc_conf2) ? file_get_contents($rc_conf2) : '';
        $cur2 = preg_replace('/\n?wg_ws_server_[^\n]+/m', '', $cur2);
        file_put_contents($rc_conf2,
            rtrim($cur2) . "\n"
            . "wg_ws_server_enable=\"YES\"\n"
            . "wg_ws_server_cert=\"{$cert_pem}\"\n"
            . "wg_ws_server_wg_port=\"{$wg_port}\"\n"
            . "wg_ws_server_port=\"443\"\n"
            . "wg_ws_server_path=\"/tunnel\"\n",
            LOCK_EX
        );
        $step['ok']  = true;
        $step['msg'] = "rc.d script written at {$rc_file} (full production version) — enabled at boot";
    }
    $steps[] = $step;

    // ----------------------------------------------------------------
    // Step 5: Start the server via rc.d (clean, boot-safe, env from rc.conf.local)
    // ----------------------------------------------------------------
    $step    = ['label' => 'Start WebSocket server'];
    $pid_file = '/var/run/wg_ws_server.pid';
    $already  = false;

    // Stop any existing instance cleanly before starting fresh
    if (file_exists($pid_file)) {
        $pid = (int)trim(file_get_contents($pid_file));
        if ($pid > 0) {
            @posix_kill($pid, SIGTERM);
            sleep(2);
            @unlink($pid_file);
            $already = true;
        }
    }

    // Start the server directly with explicit env vars — avoids rc.conf.local race conditions
    // Set env vars via putenv so they are visible to the child process
    putenv("WG_WS_CERT={$cert_pem}");
    putenv("WG_WS_PORT=443");
    putenv("WG_WS_PATH=/tunnel");
    putenv("WG_WG_PORT={$wg_port}");

    // Launch in background, capture PID
    $cmd = '/usr/local/bin/php ' . escapeshellarg($server_file)
         . ' >> ' . escapeshellarg($log_file) . ' 2>&1 & echo $!';
    exec($cmd, $pid_out);
    $new_pid = (int)trim(implode('', $pid_out));

    if ($new_pid > 0) {
        file_put_contents($pid_file, (string)$new_pid);
    }

    // Give the server up to 8 seconds to bind port 443
    $ws_listen_port = 443;
    $probe_ok  = false;
    $deadline  = time() + 8;
    while (time() < $deadline) {
        $probe = @fsockopen('127.0.0.1', $ws_listen_port, $pe, $ps, 1);
        if ($probe) { fclose($probe); $probe_ok = true; break; }
        usleep(500000);
    }

    if ($probe_ok && $new_pid > 0) {
        syslog(LOG_NOTICE, "WG Suite: WebSocket server started (pid {$new_pid}) on port {$ws_listen_port}");
        wgx_audit_log("Deployed WebSocket transport server (pid {$new_pid}) on port {$ws_listen_port}");
        $step['ok']  = true;
        $step['msg'] = ($already ? 'Restarted' : 'Started')
            . " WebSocket server (pid {$new_pid}), confirmed listening on port {$ws_listen_port}."
            . " TLS cert: {$cert_pem}.";
    } elseif ($new_pid > 0 && !$probe_ok) {
        // Process started but not listening — show last log lines for diagnosis
        $last_log = '';
        if (file_exists($log_file)) {
            $log_lines_tail = array_slice(file($log_file), -5);
            $last_log = ' Last log: ' . trim(implode(' | ', array_map('trim', $log_lines_tail)));
        }
        $step['ok']  = false;
        $step['msg'] = "Server process started (pid {$new_pid}) but is not listening on port {$ws_listen_port}."
            . " Port 443 may still be in use by another process (run: sockstat -l | grep :443 on pfSense)."
            . $last_log;
    } else {
        $last_log = '';
        if (file_exists($log_file)) {
            $log_lines_tail = array_slice(file($log_file), -5);
            $last_log = ' Last log: ' . trim(implode(' | ', array_map('trim', $log_lines_tail)));
        }
        $step['ok']  = false;
        $step['msg'] = "Server did not start. Check {$log_file} for details.{$last_log}";
    }
    $steps[] = $step;

    // ----------------------------------------------------------------
    // Step 6: Add WAN firewall rule for TCP 443
    // ----------------------------------------------------------------
    $step = ['label' => 'Add WAN firewall rule for TCP 443'];
    $filter_rules = config_get_path('filter/rule', []);
    if (!is_array($filter_rules)) $filter_rules = [];
    if (!empty($filter_rules) && !isset($filter_rules[0])) {
        $filter_rules = [$filter_rules];
    }

    // Check if the rule already exists
    $rule_exists = false;
    foreach ($filter_rules as $r) {
        if (($r['interface'] ?? '') === 'wan'
            && ($r['protocol'] ?? '') === 'tcp'
            && ($r['destination']['port'] ?? '') === '443'
            && ($r['destination']['network'] ?? '') === '(self)'
        ) {
            $rule_exists = true;
            break;
        }
    }

    if (!$rule_exists) {
        $filter_rules[] = [
            'type'        => 'pass',
            'interface'   => 'wan',
            'ipprotocol'  => 'inet46',
            'statetype'   => 'keep state',
            'protocol'    => 'tcp',
            'source'      => ['any' => true],
            'destination' => ['network' => '(self)', 'port' => '443'],
            'descr'       => 'WG Suite: Allow WebSocket transport (TCP 443)',
            'created'     => function_exists('make_config_revision_entry') ? make_config_revision_entry() : [],
        ];
        config_set_path('filter/rule', $filter_rules);
        $step['ok']  = true;
        $step['msg'] = 'Firewall rule queued — TCP 443 inbound on WAN allowed';
    } else {
        $step['ok']  = true;
        $step['msg'] = 'Firewall rule for TCP 443 already exists — no change';
    }
    $steps[] = $step;

    return $steps;
}

// === [DEV-ONLY] 6.B.NUKE — Full WGX Reset ===
// Gated by WGX_DEV_MODE constant — never active in production builds.
// To enable: define('WGX_DEV_MODE', true); in a local dev config file.
if (defined('WGX_DEV_MODE') && WGX_DEV_MODE && $_POST && isset($_POST['nuke_all'])) {
    if (!csrf_check()) {
        header("Location: vpn_wg_setup.php");
        exit;
    }

    $nuke_log   = [];
    $wg_bin     = wgx_setup_find_wg_bin();

    // ── Load WireGuard includes so wg_tunnel_sync / wg_resync are available ──
    $wg_inc_paths = [
        '/usr/local/pkg/wireguard/includes',
        '/usr/local/pkg/wireguard-kmod/includes',
        '/usr/local/share/pfSense/pkg/wireguard/includes',
    ];
    foreach ($wg_inc_paths as $_wg_path) {
        @include_once("{$_wg_path}/wg_globals.inc");
        @include_once("{$_wg_path}/wg.inc");
        @include_once("{$_wg_path}/wg_service.inc");
        if (function_exists('wg_resync') || function_exists('wg_tunnel_sync')) break;
    }
    unset($_wg_path, $wg_inc_paths);

    // ── Collect every tun_wgN name before we wipe config ──
    $all_tunnels = config_get_path('installedpackages/wireguard/tunnels/item', []);
    $tun_names   = array_column($all_tunnels, 'name');
    $tun_names   = array_filter($tun_names);

    // ── 1. Tear down live kernel interfaces ──
    // interface_bring_down() deregisters from pfSense's subsystem first so the
    // opt slot is fully freed; ifconfig destroy then removes the kernel object.
    foreach ($tun_names as $tname) {
        if (function_exists('interface_bring_down')) {
            @interface_bring_down($tname);
        }
        @mwexec("/sbin/ifconfig " . escapeshellarg($tname) . " destroy 2>/dev/null");
        $nuke_log[] = "Destroyed kernel interface: {$tname}";
    }

    // ── 2. Remove all WGX opt interface entries ──
    // Three-way match to catch every orphan variant left by previous test deploys:
    //   (a) if field starts with tun_wg   — normal case
    //   (b) descr starts with WG_VPN      — description-only orphan (if field reassigned)
    //   (c) if field matches any tun_wgN  — explicit scan of known tunnel names
    // Any matching optN is also brought down via interface_bring_down() before
    // removal so pfSense releases the slot in its internal interface assignment
    // table; without this the slot remains "owned" across reboots even after the
    // config key is deleted.
    $all_ifaces  = config_get_path('interfaces', []);
    $tun_name_set = array_flip($tun_names); // fast lookup
    foreach ($all_ifaces as $opt_key => $iface_cfg) {
        if (!preg_match('/^opt\d+$/', $opt_key)) continue;
        $bound_if  = $iface_cfg['if']    ?? '';
        $bound_dsc = $iface_cfg['descr'] ?? '';
        $is_wg = strncmp($bound_if, 'tun_wg', 6) === 0
               || strncmp($bound_dsc, 'WG_VPN', 6) === 0
               || isset($tun_name_set[$bound_if]);
        if (!$is_wg) continue;
        // Bring down cleanly before deleting from config
        if (function_exists('interface_bring_down')) {
            @interface_bring_down($opt_key);
        }
        // Also destroy the underlying kernel interface if it still exists
        if (!empty($bound_if) && strncmp($bound_if, 'tun_wg', 6) === 0) {
            @mwexec("/sbin/ifconfig " . escapeshellarg($bound_if) . " destroy 2>/dev/null");
        }
        config_del_path("interfaces/{$opt_key}");
        $nuke_log[] = "Removed interface mapping: {$opt_key} → {$bound_if} (descr: {$bound_dsc})";
    }

    // ── 3. Strip WGX firewall rules (WAN UDP WireGuard + tunnel pass rules) ──
    $filter_rules = config_get_path('filter/rule', []);
    if (!is_array($filter_rules)) $filter_rules = [];
    if (!empty($filter_rules) && !isset($filter_rules[0])) $filter_rules = [$filter_rules];

    $kept_rules = [];
    foreach ($filter_rules as $r) {
        $descr = $r['descr'] ?? '';
        // Match rules created by WG Suite deploy or WebSocket deploy
        if (
            strpos($descr, 'WG Suite') !== false
            || strpos($descr, 'Allow WireGuard') !== false
            || strpos($descr, 'WG Auto') !== false
        ) {
            $nuke_log[] = "Removed firewall rule: " . htmlspecialchars($descr);
            continue;
        }
        $kept_rules[] = $r;
    }
    config_set_path('filter/rule', $kept_rules);

    // ── 4. Strip WGX outbound NAT rules ──
    $nat_rules = config_get_path('nat/outbound/rule', []);
    if (!is_array($nat_rules)) $nat_rules = [];
    if (!empty($nat_rules) && !isset($nat_rules[0])) $nat_rules = [$nat_rules];

    $kept_nat = [];
    foreach ($nat_rules as $r) {
        $descr = $r['descr'] ?? '';
        if (
            strpos($descr, 'WG Auto') !== false
            || strpos($descr, 'WG Suite') !== false
        ) {
            $nuke_log[] = "Removed NAT rule: " . htmlspecialchars($descr);
            continue;
        }
        $kept_nat[] = $r;
    }
    config_set_path('nat/outbound/rule', $kept_nat);

    // ── 5. Wipe all WireGuard tunnels (and their peers, which live inside each tunnel entry) ──
    $peer_count   = 0;
    $tunnel_count = count($all_tunnels);
    foreach ($all_tunnels as $t) {
        $peers = $t['peers']['item'] ?? ($t['peers']['row'] ?? []);
        if (!empty($peers) && !isset($peers[0])) $peers = [$peers];
        $peer_count += count($peers);
    }
    config_set_path('installedpackages/wireguard/tunnels/item', []);
    $nuke_log[] = "Removed {$tunnel_count} tunnel(s) and {$peer_count} peer(s) from config";

    // ── 6. Clean up /tmp WebSocket conf files ──
    foreach (glob('/tmp/wg_ws_tun_wg*.conf.php') ?: [] as $f) {
        @unlink($f);
        $nuke_log[] = "Deleted WS conf file: " . basename($f);
    }

    // ── 7. Persist and reload ──
    write_config("WGX DEV: Full nuke — all tunnels, peers, firewall, NAT rules removed");
    wgx_audit_log("DEV NUKE: Removed all WGX tunnels, peers, firewall and NAT rules");

    // interfaces_configure() reconciles pfSense's internal interface-assignment
    // table against config — this is what actually releases opt slot reservations
    // so opt1 is available again for the next deploy.
    if (function_exists('interfaces_configure')) {
        @interfaces_configure();
        $nuke_log[] = "Interface subsystem reconciled (opt slots released)";
    }
    if (function_exists('filter_configure_sync')) {
        filter_configure_sync();
    } elseif (function_exists('filter_configure')) {
        filter_configure();
    }

    $savemsg    = "DEV NUKE complete — " . count($nuke_log) . " item(s) removed. pfSense config saved and filter reloaded.";
    $nuke_steps = $nuke_log;
}

// === 6.B. Form Submission (POST) & Input Parsing ===
$new_opt = '';

if ($_POST && isset($_POST['deploy_all'])) {
    if (!csrf_check()) {
        header("Location: vpn_wg_setup.php");
        exit;
    }
    wgx_stream_begin();
    wgx_stream_event('hello', ['ts' => time()]);

    $wg_desc    = !empty($_POST['wg_desc'])   ? trim($_POST['wg_desc'])   : 'WG_Tunnel';
    $wg_port    = !empty($_POST['wg_port'])   ? (int)$_POST['wg_port']   : 51820;
    $wg_ip_full = !empty($_POST['wg_ip'])     ? trim($_POST['wg_ip'])     : '10.10.10.1/24';
    $wg_ip6_full = !empty($_POST['wg_ip6'])    ? trim($_POST['wg_ip6'])    : '';
    $nat_iface  = !empty($_POST['nat_iface']) ? trim($_POST['nat_iface']) : 'wan';

    $ip_parts      = explode('/', $wg_ip_full, 2);
    $wg_ip         = $ip_parts[0];
    $wg_mask       = $ip_parts[1] ?? '24';
    $is_v6_primary = is_ipaddrv6($wg_ip);

    $network_cidr = $is_v6_primary
    ? gen_subnetv6($wg_ip, $wg_mask) . '/' . $wg_mask
    : gen_subnet($wg_ip, $wg_mask)   . '/' . $wg_mask;

    $wg_ip6        = '';
    $wg_mask6      = '';
    $network6_cidr = '';

    if (!empty($wg_ip6_full)) {
        $ip6_parts = explode('/', $wg_ip6_full, 2);
        $wg_ip6    = $ip6_parts[0];
        $wg_mask6  = $ip6_parts[1] ?? '64';
        if (is_ipaddrv6($wg_ip6)) {
            $network6_cidr = gen_subnetv6($wg_ip6, $wg_mask6) . '/' . $wg_mask6;
        } else {
            $wg_ip6 = '';
        }
    }

    // Find next available tun_wgN name
    $existing_tuns = [];
    foreach ($tunnel_items as $t) {
        if (isset($t['name'])) {
            $existing_tuns[] = $t['name'];
        }
    }
    $tun_idx = 0;
    while (in_array("tun_wg{$tun_idx}", $existing_tuns)) {
        $tun_idx++;
    }
    $tun_iface = "tun_wg{$tun_idx}";

    // Generate keypair — probe-based binary discovery with sodium fallback
    // so we don't get bitten by the broken /usr/bin/wg wrapper on pfSense+
    // 25.11 / 26.03 (which returns "Config file not specified" instead of a
    // key). See wgx_setup_gen_keypair() near the top of this file.
    wgx_step_start('crypto', 'Cryptographic Process Spawning');
    $wgx_kp  = wgx_setup_gen_keypair();
    $privkey = (string)$wgx_kp['priv'];
    $pubkey  = (string)$wgx_kp['pub'];
    $wg_bin  = wgx_setup_find_wg_bin();  // may be empty; sync steps below tolerate that
    wgx_step_done('crypto', "via {$wgx_kp['source']}");

    // ── Key validation ──────────────────────────────────────────────
    // Strict WireGuard key format check: 32 bytes base64 = 43 chars + "=".
    // Under load (kernel busy after a prior wg_toggle from a duplicate
    // submit) `wg genkey` has been observed returning empty output. Without
    // this check, an empty-key tunnel entry gets written to config —
    // exactly the "(none)" phantom users have reported.
    $key_re = '/^[A-Za-z0-9+\/]{43}=$/';
    if (!preg_match($key_re, $privkey) || !preg_match($key_re, $pubkey)) {
        $savemsg = 'Deployment aborted — could not generate a valid WireGuard '
                 . 'keypair. Both the wg binary and the sodium fallback failed — '
                 . 'this usually means PHP is missing the sodium extension. No '
                 . 'changes were made to the config.';
        wgx_step_fail('crypto', 'wg binary + sodium fallback both failed');
        wgx_stream_event('fatal', ['message' => $savemsg]);
        goto wgx_deploy_end;
    }

    $address_items = [];
    if ($is_v6_primary) {
        $address_items[] = ['address' => $wg_ip, 'mask' => $wg_mask, 'descr' => 'Tunnel_IPv6'];
        if (!empty($_POST['wg_ip4_secondary'])) {
            $v4s = explode('/', trim($_POST['wg_ip4_secondary']), 2);
            if (is_ipaddrv4($v4s[0])) {
                $address_items[] = ['address' => $v4s[0], 'mask' => $v4s[1] ?? '24', 'descr' => 'Tunnel_IPv4'];
            }
        }
    } else {
        $address_items[] = ['address' => $wg_ip, 'mask' => $wg_mask, 'descr' => 'Tunnel_IPv4'];
        if (!empty($wg_ip6)) {
            $address_items[] = ['address' => $wg_ip6, 'mask' => $wg_mask6, 'descr' => 'Tunnel_IPv6'];
        }
    }

    // Write WireGuard config enable
    $wg_pkg_config           = config_get_path('installedpackages/wireguard/config/0', []);
    $wg_pkg_config['enable'] = 'on';
    config_set_path('installedpackages/wireguard/config/0', $wg_pkg_config);

    // Append new tunnel
    $tunnels   = config_get_path('installedpackages/wireguard/tunnels/item', []);
    // === WebSocket Transport (optional) ===
    $ws_enabled      = isset($_POST['ws_enabled']) && $_POST['ws_enabled'] === '1';
    $ws_remote_ip    = '127.0.0.1'; // Server runs on this pfSense box — always loopback
    $ws_remote_port  = (int)($_POST['ws_remote_port'] ?? 443);
    $ws_path         = trim($_POST['ws_path']         ?? '/tunnel');
    $ws_tls          = isset($_POST['ws_tls']) && $_POST['ws_tls'] === '1';
    $ws_reconnect    = max(1, (int)($_POST['ws_reconnect'] ?? 5));
    $ws_hs_timeout   = max(5, (int)($_POST['ws_hs_timeout'] ?? 10));

    // Sanitise: strip CR/LF to prevent header injection (mirrors wg_ws_core.php [SEC-1])
    $ws_path = str_replace(["\r", "\n"], '', $ws_path);
    if ($ws_path === '' || $ws_path[0] !== '/') {
        $ws_path = '/tunnel';
    }

    $tunnel_entry = [
        'name'       => $tun_iface,
        'enable'     => 'on',
        'enabled'    => 'yes',
        'descr'      => $wg_desc,
        'listenport' => (string)$wg_port,
        'privatekey' => $privkey,
        'publickey'  => $pubkey,
        'addresses'  => ['row' => $address_items],
        'mtu'        => '1420',
    ];

    if ($ws_enabled && !empty($ws_remote_ip)) {
        $tunnel_entry['wgx_ws'] = [
            'enabled'    => '1',
            'remote_ip'  => $ws_remote_ip,
            'remote_port' => (string)$ws_remote_port,
            'ws_path'    => $ws_path,
            'tls'        => $ws_tls ? '1' : '0',
            'reconnect'  => (string)$ws_reconnect,
            'hs_timeout' => (string)$ws_hs_timeout,
        ];

        // Write the generated config file for the daemon to read at startup
        $ws_conf_path = "/tmp/wg_ws_{$tun_iface}.conf.php";
        $ws_conf_content = "<?php\n" .
        "\$local_wg_ip        = '127.0.0.1';\n" .
        "\$local_wg_port      = {$wg_port};\n" .
        "\$remote_server_ip   = " . var_export($ws_remote_ip, true) . ";\n" .
        "\$remote_server_port = {$ws_remote_port};\n" .
        "\$gateway_host       = " . var_export($ws_remote_ip, true) . ";\n" .
        "\$ws_path            = " . var_export($ws_path, true) . ";\n" .
        "\$use_tls            = " . ($ws_tls ? 'true' : 'false') . ";\n" .
        "\$reconnect_delay    = {$ws_reconnect};\n" .
        "\$handshake_timeout  = {$ws_hs_timeout};\n" .
        "\$trusted_udp_ip     = '127.0.0.1';\n";
        file_put_contents($ws_conf_path, $ws_conf_content);
        chmod($ws_conf_path, 0600);

        syslog(LOG_NOTICE, "WG Suite: WebSocket transport enabled for {$tun_iface} → {$ws_remote_ip}:{$ws_remote_port}");
        wgx_audit_log("WebSocket transport enabled for tunnel {$tun_iface}");
    }

    // Idempotency guard: if the same descr + listenport combination is
    // already in the tunnel list, don't append a second time. Protects
    // against duplicate submissions racing past the POST-Redirect-GET
    // pattern (e.g. mid-air click before the redirect lands).
    $already_present = false;
    foreach ($tunnels as $existing_t) {
        if (
            is_array($existing_t)
            && ($existing_t['name']       ?? '') === $tun_iface
            && ($existing_t['descr']      ?? '') === $wg_desc
            && (string)($existing_t['listenport'] ?? '') === (string)$wg_port
        ) {
            $already_present = true;
            break;
        }
    }
    if (!$already_present) {
        $tunnels[] = $tunnel_entry;
        config_set_path('installedpackages/wireguard/tunnels/item', $tunnels);
    }

    // === 6.D. pfSense Interface Mapping (MOVED UP) ===
    // IMPORTANT: We must claim the opt slot and map it in the config memory
    // BEFORE calling write_config() or wg_tunnel_sync(). When write_config() runs,
    // it triggers package XML hooks which cause the official WireGuard package
    // to silently consume the first available opt slot if we haven't already explicitly claimed it.
    for ($i = 1; $i <= 99; $i++) {
        // Checking for an empty 'if' safely ignores ghost/deleted interfaces
        if (empty(config_get_path("interfaces/opt{$i}/if"))) {
            $new_opt = "opt{$i}";
            break;
        }
    }

    $iface_descr = $tun_idx === 0 ? 'WG_VPN' : 'WG_VPN' . ($tun_idx + 1);

    $iface_ipv4   = '';
    $iface_mask4  = '24';
    $iface_ipv6   = '';
    $iface_mask6  = '128';

    if ($is_v6_primary) {
        if (!empty($_POST['wg_ip4_secondary'])) {
            $v4s = explode('/', trim($_POST['wg_ip4_secondary']), 2);
            if (is_ipaddrv4($v4s[0])) {
                $iface_ipv4  = $v4s[0];
                $iface_mask4 = $v4s[1] ?? '24';
            }
        }
        $iface_ipv6  = $wg_ip;
        $iface_mask6 = $wg_mask;
    } else {
        $iface_ipv4  = $wg_ip;
        $iface_mask4 = $wg_mask;
        if (!empty($wg_ip6)) {
            $iface_ipv6  = $wg_ip6;
            $iface_mask6 = $wg_mask6;
        }
    }

    $iface_cfg = [
        'enable'      => 'on',
        'if'          => $tun_iface,
        'descr'       => $iface_descr,
        'mtu'         => '1420',
        'mss'         => '1380',
    ];

    if (!empty($iface_ipv4)) {
        $iface_cfg['ipaddr']  = $iface_ipv4;
        $iface_cfg['subnet']  = $iface_mask4;
    } else {
        $iface_cfg['ipaddr']  = 'none';
    }

    if (!empty($iface_ipv6)) {
        $iface_cfg['ipaddrv6'] = $iface_ipv6;
        $iface_cfg['subnetv6'] = $iface_mask6;
    } else {
        $iface_cfg['ipaddrv6'] = 'none';
    }

    if (!empty($new_opt)) {
        config_set_path("interfaces/{$new_opt}", $iface_cfg);
    }

    // Firewall rules — check for duplicates before adding
    $filter_rules = config_get_path('filter/rule', []);
    if (!is_array($filter_rules)) {
        $filter_rules = [];
    } elseif (!empty($filter_rules) && !isset($filter_rules[0])) {
        $filter_rules = [$filter_rules];
    }

    // WAN inbound rule — check by port to avoid duplicates
    $wan_rule_exists = false;
    foreach ($filter_rules as $r) {
        if (
            ($r['interface'] ?? '') === 'wan' &&
            ($r['protocol']  ?? '') === 'udp' &&
            ($r['destination']['port'] ?? '') === (string)$wg_port
        ) {
            $wan_rule_exists = true;
            break;
        }
    }
    if (!$wan_rule_exists) {
        $filter_rules[] = [
            'type'        => 'pass',
            'interface'   => 'wan',
            'ipprotocol'  => 'inet46',
            'statetype'   => 'keep state',
            'protocol'    => 'udp',
            'source'      => ['any' => true],
            'destination' => ['network' => '(self)', 'port' => (string)$wg_port],
            'descr'       => "Allow WireGuard Inbound ({$wg_desc})",
            'created'     => function_exists('make_config_revision_entry') ? make_config_revision_entry() : [],
        ];
    }

    // Tunnel traffic rule — check by interface opt name to avoid duplicates
    $tun_rule_exists = false;
    foreach ($filter_rules as $r) {
        if (($r['interface'] ?? '') === $new_opt) {
            $tun_rule_exists = true;
            break;
        }
    }
    if (!$tun_rule_exists && !empty($new_opt)) {
        $filter_rules[] = [
            'type'         => 'pass',
            'interface'    => $new_opt,
            'ipprotocol'   => 'inet46',
            'statetype'    => 'keep state',
            'source'       => ['any' => true],
            'destination'  => ['any' => true],
            'descr'        => "Allow WireGuard Traffic ({$wg_desc})",
            'created'      => function_exists('make_config_revision_entry') ? make_config_revision_entry() : [],
        ];
    }
    config_set_path('filter/rule', $filter_rules);

    // === 6.E. Outbound NAT ===
    $nat_mode = config_get_path('nat/outbound/mode', '');
    if (empty($nat_mode) || $nat_mode === 'automatic') {
        config_set_path('nat/outbound/mode', 'hybrid');
    }

    $nat_rules = config_get_path('nat/outbound/rule', []);
    if (!is_array($nat_rules)) {
        $nat_rules = [];
    } elseif (!empty($nat_rules) && !isset($nat_rules[0])) {
        $nat_rules = [$nat_rules];
    }

    $nat_cidrs_to_add = array_filter([$network_cidr, $network6_cidr]);
    foreach ($nat_cidrs_to_add as $nat_cidr) {
        $already_exists = false;
        foreach ($nat_rules as $r) {
            if (($r['source']['network'] ?? '') === $nat_cidr) {
                $already_exists = true;
                break;
            }
        }
        if (!$already_exists) {
            $nat_rules[] = [
                'source'      => ['network' => $nat_cidr],
                'sourceport'  => '',
                'descr'       => "WG Auto Setup: Outbound NAT for {$wg_desc}",
                'target'      => '',
                'interface'   => $nat_iface,
                'destination' => ['any' => true],
                'natport'     => '',
                'protocol'    => 'any',
                'created'     => function_exists('make_config_revision_entry') ? make_config_revision_entry() : [],
            ];
        }
    }
    config_set_path('nat/outbound/rule', $nat_rules);

    // === 6.E.1. Multi-Site Mesh Routing (FRR OSPF) ===
    $ospf_msg = '';
    if (!empty($new_opt) && isset($_POST['mesh_routing']) && $_POST['mesh_routing'] === 'yes') {
        if (is_dir('/usr/local/pkg/frr')) {
            $ospf_ifaces = config_get_path('installedpackages/frrospfinterfaces/config', []);
            $ospf_exists = false;
            foreach ($ospf_ifaces as $ospf_if) {
                if (($ospf_if['interface'] ?? '') === $new_opt) {
                    $ospf_exists = true;
                    break;
                }
            }
            if (!$ospf_exists) {
                $ospf_ifaces[] = [
                    'interface'     => $new_opt,
                    'descr'         => "WG_Mesh_{$tun_iface}",
                    'networktype'   => 'pointToPoint',
                    'cost'          => '10',
                    'hellointerval' => '10',
                    'deadinterval'  => '40',
                ];
                config_set_path('installedpackages/frrospfinterfaces/config', $ospf_ifaces);
                $ospf_msg = " [FRR OSPF Linked]";
                syslog(LOG_NOTICE, "WG Suite: FRR OSPF automatically configured for new Mesh VPN ({$tun_iface}).");
                wgx_audit_log("Tunnel created: {$tun_iface} — FRR OSPF mesh routing enabled");
            }
        } else {
            $ospf_msg = " [FRR pkg missing - skipped OSPF]";
        }
    }

    // Write all config array changes sequentially at the very end
    wgx_step_start('xml', 'XML Config Writing & Backup');
    write_config("WG Suite: Finalized Deploy, Interface Mapping, Rules & Routing");
    wgx_step_done('xml');

    // Load WireGuard includes
    $wg_inc_paths = [
        '/usr/local/pkg/wireguard/includes',
        '/usr/local/pkg/wireguard-kmod/includes',
        '/usr/local/share/pfSense/pkg/wireguard/includes',
    ];
    foreach ($wg_inc_paths as $_wg_path) {
        @include_once("{$_wg_path}/wg_globals.inc");
        @include_once("{$_wg_path}/wg.inc");
        @include_once("{$_wg_path}/wg_service.inc");
        if (function_exists('wg_resync') || function_exists('wg_tunnel_sync')) break;
    }
    unset($_wg_path, $wg_inc_paths);

    wgx_step_start('wg', 'WireGuard Subsystem Resync');
    if (function_exists('wg_toggle_wireguard')) {
        wg_toggle_wireguard();
    }
    if (function_exists('wg_tunnel_sync')) {
        wg_tunnel_sync([$tun_iface], true);
    } elseif (function_exists('wg_resync')) {
        wg_resync();
        sync_package("wireguard");
    } else {
        sync_package("wireguard");
    }
    wgx_step_done('wg', "loaded {$tun_iface} into kernel");

    wgx_step_start('routing', 'System Routing and Gateway Rebuilds');
    if (!empty($new_opt) && function_exists('interface_configure')) {
        @interface_configure($new_opt, true);
    }
    wgx_step_done('routing', !empty($new_opt) ? "interface {$new_opt} up" : '');

    wgx_step_start('firewall', 'Global Firewall Reload');
    if (function_exists('filter_configure_sync')) {
        filter_configure_sync();
    } elseif (function_exists('filter_configure')) {
        filter_configure();
    }
    wgx_step_done('firewall');

    $v6_info  = !empty($wg_ip6) ? " | IPv6: {$wg_ip6}/{$wg_mask6}" : '';
    $savemsg  = "Deployment Complete! Interface {$tun_iface} created. IPv4: {$wg_ip}/{$wg_mask}{$v6_info}. Routing and NAT applied.{$ospf_msg}";

    // === WebSocket server auto-deploy ===
    if ($ws_enabled && isset($tunnel_entry['wgx_ws'])) {
        // $ws_remote_ip is empty when running on-box — that is correct here.
        // The "remote server" IS this pfSense box, so we deploy the server locally.
        $webui_port    = !empty($_POST['ws_webui_port']) ? (int)$_POST['ws_webui_port'] : 8443;
        wgx_step_start('ws', 'WebSocket Server Deployment');
        $ws_deploy     = wgx_deploy_ws_server($wg_port, $webui_port, $tun_iface);
        $ws_all_ok     = !in_array(false, array_column($ws_deploy, 'ok'), true);
        if ($ws_all_ok) {
            wgx_step_done('ws', 'server listening on 443');
        } else {
            wgx_step_fail('ws', 'see step details below');
        }
        $all_ok        = !in_array(false, array_column($ws_deploy, 'ok'), true);

        // The deploy function already probed port 443 internally.
        // This final check confirms it is still responding.
        if ($all_ok) {
            $probe_ok    = false;
            $final_probe = @fsockopen('127.0.0.1', 443, $pe, $ps, 2);
            if ($final_probe) { fclose($final_probe); $probe_ok = true; }
            $ws_deploy[] = [
                'ok'    => $probe_ok,
                'label' => 'Final service probe',
                'msg'   => $probe_ok
                    ? "WebSocket server confirmed listening on port 443."
                    : "Warning: server not responding on port 443. If port 443 is still used by the web GUI, go to System > Advanced > Admin Access and move it to port 8443, then re-run Setup.",
            ];
            $all_ok = $probe_ok;
        }

        $savemsg      .= $all_ok
        ? " WebSocket server deployed and verified."
        : " WebSocket server deployment had issues — see details below.";
        // Store steps so the UI can render them
        $ws_deploy_steps = $ws_deploy;
    }

    // ── Persist WS-deploy config mutations ─────────────────────────
    // wgx_deploy_ws_server() modified system/webgui/port and filter/rule
    // in memory but did NOT write_config, so those changes would be lost
    // when the request ends. Save once here.
    if ($ws_enabled) {
        wgx_step_start('commit', 'Final Configuration Commit');
        write_config('WG Suite: WebSocket transport deploy — persist port/rule changes');
        wgx_step_done('commit');
    }

    // ── Success — Post-Redirect-Get so a reload doesn't re-deploy ─
    // The rc.restart_webgui and any WS server start run in a shutdown
    // hook below, AFTER the response has been flushed to the browser —
    // eliminates the perceived spinner-lockup.
    wgx_deploy_end:
    if (!empty($savemsg) && strpos($savemsg, 'Deployment Complete!') === 0) {
        // Stash results in the session so the follow-up GET can render them,
        // then PRG to prevent re-submit on refresh.
        if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
        $_SESSION['wgx_setup_result'] = [
            'savemsg'         => $savemsg,
            'ws_deploy_steps' => $ws_deploy_steps ?? [],
        ];
        // Fire-and-forget the slow stuff after we send the response.
        wgx_schedule_post_response_tasks();

        // Streaming mode: tell the client we're done and where to go next.
        // No Location: header — the client navigates on receiving 'done'.
        if ($GLOBALS['wgx_stream_mode']) {
            $stream_target = 'vpn_wg_setup.php?deployed=1';
            $stream_port   = 0;
            if (!empty($GLOBALS['wgx_webgui_restart_needed'])) {
                $stream_port   = (int)($GLOBALS['wgx_new_webui_port'] ?? 8443);
                $stream_target = '';  // client will build absolute URL from window.location
            }
            wgx_stream_event('done', [
                'navigate'    => $stream_target,
                'port_change' => !empty($GLOBALS['wgx_webgui_restart_needed']),
                'new_port'    => $stream_port,
                'message'     => $savemsg,
            ]);
            exit;
        }

        if (empty($GLOBALS['wgx_webgui_restart_needed'])) {
            // Same-port deploy — normal PRG works.
            header('Location: vpn_wg_setup.php?deployed=1');
            exit;
        }

        // Port-change deploy: the browser can't follow a Location: back to
        // the port it POSTed on because that port is about to die. Render a
        // self-contained interstitial that polls the new port and hops the
        // browser over as soon as it's up.
        $new_port    = (int)($GLOBALS['wgx_new_webui_port'] ?? 8443);
        $safe_msg    = htmlspecialchars($savemsg, ENT_QUOTES, 'UTF-8');
        $steps_html  = '';
        foreach (($ws_deploy_steps ?? []) as $st) {
            $ok    = !empty($st['ok']);
            $lbl   = htmlspecialchars((string)($st['label'] ?? ''), ENT_QUOTES, 'UTF-8');
            $smsg  = htmlspecialchars((string)($st['msg']   ?? ''), ENT_QUOTES, 'UTF-8');
            $icon  = $ok ? '&#x2713;' : '&#x2717;';
            $color = $ok ? '#4caf50'  : '#e57373';
            $steps_html .= "<li><span style=\"color:{$color};font-weight:600;\">{$icon}</span> "
                        .  "<strong>{$lbl}</strong> &mdash; {$smsg}</li>";
        }
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
        ?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WG Suite &mdash; Deploy Complete</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #1e2836; color: #e5e9f0; margin: 0; padding: 40px 20px; }
  .card { max-width: 640px; margin: 0 auto; background: #26334a;
          border-radius: 8px; padding: 32px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
  h1 { margin: 0 0 12px 0; font-size: 22px; color: #4caf50; }
  h1 .check { display: inline-block; width: 28px; height: 28px; border-radius: 50%;
              background: #4caf50; color: #fff; text-align: center; line-height: 28px;
              font-weight: 700; margin-right: 8px; vertical-align: -4px; }
  p  { line-height: 1.5; }
  ul.steps { list-style: none; padding: 0; margin: 12px 0; font-size: 13px;
             background: #1e2836; border-radius: 6px; padding: 12px 18px; }
  ul.steps li { padding: 4px 0; }
  .waiting { display: flex; align-items: center; gap: 14px; margin: 28px 0 20px;
             padding: 16px 20px; background: #1e2836; border-left: 4px solid #ffb74d;
             border-radius: 4px; }
  .spinner { width: 22px; height: 22px; border: 3px solid rgba(255,255,255,0.15);
             border-top-color: #ffb74d; border-radius: 50%;
             animation: spin 0.9s linear infinite; flex-shrink: 0; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .waiting.up { border-left-color: #4caf50; }
  .waiting.up .spinner { border-top-color: #4caf50; }
  .cta { display: inline-block; margin-top: 8px; padding: 10px 22px;
         background: #4caf50; color: #fff; text-decoration: none; border-radius: 4px;
         font-weight: 600; }
  .cta:hover { background: #43a047; }
  .muted { color: #90a4ae; font-size: 13px; }
  code { background: #1e2836; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<div class="card">
  <h1><span class="check">&#x2713;</span> Tunnel deployed</h1>
  <p><?= $safe_msg ?></p>
  <?php if ($steps_html !== ''): ?>
    <ul class="steps"><?= $steps_html ?></ul>
  <?php endif; ?>
  <div id="wgxWait" class="waiting">
    <div class="spinner"></div>
    <div>
      <div id="wgxWaitMsg"><strong>Waiting for the pfSense web UI on port <?= $new_port ?>&hellip;</strong></div>
      <div class="muted">This usually takes 5&ndash;15 seconds while nginx restarts.</div>
    </div>
  </div>
  <p>If nothing happens automatically, click here:</p>
  <p><a id="wgxGo" class="cta" href="#">Continue to pfSense on port <?= $new_port ?></a></p>
  <p class="muted">The web UI has moved because the WebSocket server now owns port&nbsp;443. You can move it back in <code>System &gt; Advanced &gt; Admin Access</code> at any time.</p>
</div>
<script>
(function() {
    var newPort = <?= (int)$new_port ?>;
    var target  = window.location.protocol + '//' + window.location.hostname +
                  ':' + newPort + '/vpn_wg_setup.php?deployed=1';
    document.getElementById('wgxGo').href = target;

    var attempts = 0;
    var maxAttempts = 120;   // 60 seconds at 500 ms
    var startDelay  = 2500;  // give the shutdown handler a moment

    function markUp() {
        var wait = document.getElementById('wgxWait');
        var msg  = document.getElementById('wgxWaitMsg');
        if (wait) { wait.classList.add('up'); }
        if (msg)  { msg.innerHTML = '<strong>Web UI is back up. Redirecting&hellip;</strong>'; }
        setTimeout(function() { window.location.href = target; }, 250);
    }

    function poll() {
        attempts++;
        if (attempts > maxAttempts) { return; } // give up — fallback link stays

        // fetch with no-cors: resolves the moment the new port answers, rejects
        // while it's still down. We can't read the response and we don't need to.
        fetch(target, { method: 'GET', mode: 'no-cors', cache: 'no-store',
                        credentials: 'omit', redirect: 'manual' })
            .then(function()  { markUp(); })
            .catch(function() { setTimeout(poll, 500); });
    }
    setTimeout(poll, startDelay);
})();
</script>
</body>
</html>
<?php
        exit;
    }
}

// ── Post-Redirect-Get pickup ───────────────────────────────────────────
// After a successful deploy the browser lands here via GET. Pull the stashed
// results out of the session so the page renders exactly like the direct
// POST response would have.
if (
    $_SERVER['REQUEST_METHOD'] === 'GET'
    && isset($_GET['deployed'])
    && empty($savemsg)
) {
    if (session_status() !== PHP_SESSION_ACTIVE) { @session_start(); }
    if (!empty($_SESSION['wgx_setup_result'])) {
        $savemsg         = (string)($_SESSION['wgx_setup_result']['savemsg']         ?? '');
        $ws_deploy_steps = (array) ($_SESSION['wgx_setup_result']['ws_deploy_steps'] ?? []);
        unset($_SESSION['wgx_setup_result']);
    }
}

// ── Deferred post-response tasks ───────────────────────────────────────
// The web-UI restart AND the WebSocket server startup poll (up to 8s)
// happen here — AFTER the browser has the redirect. Uses
// fastcgi_finish_request() when available; falls back to output-buffer
// close + connection-close header so the client sees the response
// immediately regardless of how PHP is fronted.
function wgx_schedule_post_response_tasks(): void
{
    register_shutdown_function(function () {
        // Flush the response to the client first.
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } else {
            @ignore_user_abort(true);
            @header('Connection: close');
            @header('Content-Length: ' . ob_get_length());
            while (ob_get_level() > 0) { @ob_end_flush(); }
            @flush();
        }
        // Now do the slow stuff without the browser waiting on us.
        if (!empty($GLOBALS['wgx_webgui_restart_needed'])) {
            @mwexec('/etc/rc.restart_webgui &');
        }
    });
}

// === 6.F. Setup Wizard UI ===
$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("Setup")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
include("head.inc");
?>
<style>
@media (max-width: 767px) {
    .col-sm-3, .col-sm-4, .col-sm-6, .col-sm-8, .col-sm-9 { width: 100% !important; }
    .form-horizontal .control-label { text-align: left !important; padding-top: 0; margin-bottom: 4px; }
    .panel-body { padding: 10px; }
    .modal-dialog { margin: 5px; }
    .modal-body { padding: 10px; }
    .btn-block-xs { display: block; width: 100%; margin-bottom: 4px; }
    .table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
}
</style>
<?php

$tab_array   = [];
$tab_array[] = [gettext("Dashboard"), false, "/wgx/vpn_wg_dashboard.php"];
$tab_array[] = [gettext("Export"),    false, "/wgx/vpn_wg_export.php"];
$tab_array[] = [gettext("Setup"),     true,  "/wgx/vpn_wg_setup.php"];
$tab_array[] = [gettext("Audit"),     false, "/wgx/vpn_wg_audit.php"];
$tab_array[] = [gettext("Map"),       false, "/wgx/vpn_wg_map.php"];
display_top_tabs($tab_array);

if (isset($savemsg)) {
    print_info_box($savemsg, 'success');
    if (isset($tun_iface)) {
        echo '<div class="alert alert-info" style="margin-top:8px;">'
        . '<i class="fa fa-arrow-right"></i> <strong>Next step:</strong> '
        . 'Go to the <a href="/wgx/vpn_wg_export.php" class="alert-link">Export page</a> '
        . 'to provision peers for this tunnel.'
        . '</div>';
    }
}
if (isset($ws_deploy_steps)) {
    echo '<div class="panel panel-default" style="margin-top:10px;">';
    echo '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-plug"></i> WebSocket Server Deployment</h3></div>';
    echo '<div class="panel-body"><ul class="list-group" style="margin-bottom:0;">';
    foreach ($ws_deploy_steps as $s) {
        $icon  = $s['ok'] ? 'fa-check text-success' : 'fa-times text-danger';
        $label = htmlspecialchars($s['label']);
        $msg   = $s['msg'];   // already safe — no user input reflected here
        echo "<li class=\"list-group-item\">"
        . "<i class=\"fa {$icon}\"></i>&nbsp; <strong>{$label}</strong>"
        . " &mdash; {$msg}</li>";
    }
    echo '</ul></div></div>';
}
?>

<?php
// === [DEV-ONLY] Nuke result display — only shown when WGX_DEV_MODE is active ===
if (defined('WGX_DEV_MODE') && WGX_DEV_MODE && isset($nuke_steps) && !empty($nuke_steps)): ?>
    <div class="panel panel-danger" style="margin-bottom:10px;">
    <div class="panel-heading">
    <h3 class="panel-title"><i class="fa fa-bomb"></i> DEV NUKE — Actions Taken</h3>
    </div>
    <div class="panel-body" style="padding:8px 15px;">
    <ul class="list-unstyled" style="margin:0; font-family:monospace; font-size:12px;">
    <?php foreach ($nuke_steps as $step): ?>
    <li><i class="fa fa-check text-danger"></i> <?= htmlspecialchars($step) ?></li>
    <?php endforeach; ?>
    </ul>
    </div>
    </div>
    <?php endif; ?>

    <?php if (defined('WGX_DEV_MODE') && WGX_DEV_MODE): ?>
    <div class="panel panel-default" style="border-color:#c0392b; margin-bottom:15px;">
    <div class="panel-heading" style="background:#c0392b; color:#fff; cursor:pointer;"
    onclick="document.getElementById('nukeBody').style.display =
    document.getElementById('nukeBody').style.display === 'none' ? '' : 'none';">
    <h3 class="panel-title" style="color:#fff;">
    <i class="fa fa-bomb"></i>&nbsp; DEV ONLY — Full Reset
    <small style="opacity:.75; margin-left:8px;">(click to expand &mdash; remove before submission)</small>
    </h3>
    </div>
    <div id="nukeBody" style="display:none;">
    <div class="panel-body" style="background:#fff5f5;">
    <p class="text-danger" style="margin-bottom:10px;">
    <i class="fa fa-exclamation-triangle"></i>
    <strong>Destroys every WGX tunnel, all peers, all WGX firewall rules, and all WGX NAT rules.</strong>
    Live kernel interfaces are torn down immediately. Use this to start completely fresh.
    </p>
    <form action="vpn_wg_setup.php" method="post" id="nukeForm">
    <button type="button" class="btn btn-danger btn-sm"
    onclick="if(confirm('NUKE everything? This removes all WGX tunnels, peers, firewall and NAT rules and cannot be undone.')){document.getElementById('nukeForm').submit();}">
    <i class="fa fa-bomb icon-embed-btn"></i> Nuke All Tunnels &amp; Rules
    </button>
    <span class="text-muted" style="margin-left:12px; font-size:12px;">
    Removes all <code>tun_wgN</code> interfaces, associated <code>optN</code> mappings,
WGX firewall rules, WGX NAT rules, and all peers.
</span>
<input type="hidden" name="nuke_all" value="1">
</form>
</div>
</div>
</div>
<?php endif; // WGX_DEV_MODE ?>

<div class="panel panel-default">
<div class="panel-heading">
<h2 class="panel-title">WireGuard Tunnel Setup</h2>
</div>
<div class="panel-body">
<form action="vpn_wg_setup.php" method="post" name="iform" id="iform" style="margin-bottom: 0;">
<table class="table table-striped table-hover">
<tbody>
<tr>
<td style="width:22%;"><strong>Tunnel Description</strong></td>
<td>
<input type="text" class="form-control" name="wg_desc" value="WG_Tunnel">
</td>
</tr>
<tr>
<td><strong>Listen Port</strong></td>
<td>
<input type="number" class="form-control" name="wg_port" id="wg_port"
value="<?= htmlspecialchars((string)$next_port) ?>" min="1" max="65535">
<span class="help-block" id="wg_port_help">
UDP port WireGuard listens on. Auto-incremented from existing tunnels.
</span>
<div id="wg_port_ws_notice" style="display:none; margin-top:6px;">
<span class="label label-info"><i class="fa fa-plug"></i> WebSocket Transport Active</span>
<span class="text-muted" style="font-size:12px; margin-left:6px;">
WireGuard keeps its UDP port above for local bridging.
Peers will connect via <strong>TCP 443</strong> through the WebSocket server — not directly to this port.
</span>
</div>
</td>
</tr>
<tr>
<td><strong>Tunnel IPv4 Address / CIDR</strong></td>
<td>
<input type="text" class="form-control" name="wg_ip"
value="<?= htmlspecialchars($next_v4) ?>"
placeholder="e.g. 10.10.10.1/24">
<span class="help-block">
Primary tunnel address. Can be IPv4 <em>or</em> IPv6.
</span>
</td>
</tr>
<tr>
<td>
<strong>Tunnel IPv6 Address / Prefix</strong>
<span class="text-muted"> (optional)</span>
</td>
<td>
<input type="text" class="form-control" name="wg_ip6"
value="<?= htmlspecialchars($next_v6) ?>"
placeholder="e.g. fd00:10:10:10::1/64">
<span class="help-block">
Leave blank for IPv4-only. A <code>fd00::/8</code> ULA prefix is recommended.
</span>
</td>
</tr>
<tr>
<td><strong>Outbound NAT Interface</strong></td>
<td>
<select name="nat_iface" class="form-control">
<?php foreach ($local_interfaces as $if => $desc): ?>
<option value="<?= htmlspecialchars($if) ?>"
<?= ($if === 'wan') ? 'selected' : '' ?>>
<?= htmlspecialchars($desc) ?>
</option>
<?php endforeach; ?>
</select>
</td>
</tr>
<tr>
<td>
<strong>Multi-Site Mesh Routing</strong>
<span class="text-muted"> (Advanced)</span>
</td>
<td>
<div class="checkbox">
<label>
<input type="checkbox" name="mesh_routing" value="yes">
<strong>Enable Dynamic Routing Injection (FRR / OSPF)</strong>
</label>
</div>
<span class="help-block">
Requires the pfSense FRR package to be installed.
</span>
</td>
</tr>
<tr>
<td>
<strong>WebSocket Transport</strong>
<span class="text-muted"> (Advanced)</span>
</td>
<td>
<div class="checkbox" style="margin-bottom:8px;">
<label>
<input type="checkbox" name="ws_enabled" value="1" id="wsEnabledCheck"
onchange="
document.getElementById('wsTransportOptions').style.display  = this.checked ? '' : 'none';
document.getElementById('wg_port_ws_notice').style.display   = this.checked ? '' : 'none';
document.getElementById('wg_port_help').style.display        = this.checked ? 'none' : '';
">
<strong>Tunnel WireGuard UDP over WebSocket (port 443)</strong>
</label>
</div>
<div id="wsTransportOptions" style="display:none;">
<div class="row" style="margin-bottom:6px;">
<div class="col-sm-3">
<label class="control-label" style="font-weight:normal;">Port</label>
<input type="number" class="form-control input-sm" name="ws_remote_port" value="443" min="1" max="65535">
</div>
<div class="col-sm-3">
<label class="control-label" style="font-weight:normal;">WS Path</label>
<input type="text" class="form-control input-sm" name="ws_path" value="/tunnel" placeholder="/tunnel">
</div>
</div>
<div class="row" style="margin-bottom:6px;">
<div class="col-sm-3">
<label class="control-label" style="font-weight:normal;">Reconnect Delay (s)</label>
<input type="number" class="form-control input-sm" name="ws_reconnect" value="5" min="1" max="300">
</div>
<div class="col-sm-3">
<label class="control-label" style="font-weight:normal;">Handshake Timeout (s)</label>
<input type="number" class="form-control input-sm" name="ws_hs_timeout" value="10" min="5" max="60">
</div>
<div class="col-sm-6" style="padding-top:22px;">
<div class="checkbox" style="margin:0;">
<label>
<input type="checkbox" name="ws_tls" value="1" checked>
<strong>Enable TLS</strong> (recommended — verifies server certificate)
</label>
</div>
</div>
</div>
<span class="help-block">
Wraps WireGuard UDP inside a WebSocket connection. Useful for networks that block UDP.
The WebSocket server and firewall rule are configured automatically on deploy.
</span>
<?php
// Only prompt to move the web UI when it's still on 443 (or unset — pfSense
// treats an empty webgui port as 443). If a previous WebSocket deploy
// already moved it (e.g. to 8443 or 64443), don't ask the user again;
// the deploy handler is idempotent and skips the move anyway. Show a
// short info line so the user knows what state the box is in.
$wgx_cur_webui_port = (int)(config_get_path('system/webgui/port', '') ?: 443);
if ($wgx_cur_webui_port === 443):
?>
<div class="row" style="margin-top:8px;">
<div class="col-sm-3">
<label class="control-label" style="font-weight:normal;">Move web UI to port</label>
<input type="number" class="form-control input-sm" name="ws_webui_port" value="8443" min="1024" max="65535">
<span class="help-block" style="font-size:11px;">Port 443 must be free for the WebSocket server. The web UI will move here.</span>
</div>
</div>
<?php else: ?>
<div style="margin-top:8px; padding:8px 12px; background:rgba(76,175,80,0.08); border-left:3px solid #4caf50; border-radius:2px; font-size:12px;">
<i class="fa fa-check-circle" style="color:#4caf50;"></i>
Web UI is already on port <strong><?= (int)$wgx_cur_webui_port ?></strong>, so port 443 is free for the WebSocket server. No move needed.
</div>
<?php endif; ?>
</div>
</td>
</tr>
</tbody>
</table>
<div style="margin-top:15px; padding-left:22%;">
<button class="btn btn-sm btn-primary" type="submit" name="deploy_all" value="Deploy">
<i class="fa fa-save icon-embed-btn"></i> Deploy Tunnel
</button>
</div>
</form>
</div>
</div>

<div id="wgxDeployOverlay" style="display:none;position:fixed;inset:0;background:rgba(10,15,25,0.72);z-index:9999;color:#e5e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;overflow-y:auto;">
    <div style="max-width:560px;margin:0 auto;padding:8vh 24px 40px;">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px;">
            <div id="wgxOverlaySpinner" style="width:44px;height:44px;border:5px solid rgba(255,255,255,0.15);border-top-color:#4caf50;border-radius:50%;animation:wgxSpin 0.9s linear infinite;flex-shrink:0;"></div>
            <div>
                <div id="wgxOverlayTitle" style="font-size:20px;font-weight:600;line-height:1.2;">Deploying tunnel&hellip;</div>
                <div id="wgxDeployHint" style="margin-top:6px;font-size:13px;opacity:0.75;">Please don't refresh or close this tab.</div>
            </div>
        </div>
        <ol id="wgxStepList" style="list-style:none;padding:0;margin:0;background:#1e2836;border-radius:8px;padding:12px 8px;box-shadow:0 8px 32px rgba(0,0,0,0.35);">
            <li data-id="crypto"   class="wgx-step wgx-pending"><span class="wgx-icon"></span><span class="wgx-label">Cryptographic Process Spawning</span><span class="wgx-detail"></span></li>
            <li data-id="xml"      class="wgx-step wgx-pending"><span class="wgx-icon"></span><span class="wgx-label">XML Config Writing &amp; Backup</span><span class="wgx-detail"></span></li>
            <li data-id="wg"       class="wgx-step wgx-pending"><span class="wgx-icon"></span><span class="wgx-label">WireGuard Subsystem Resync</span><span class="wgx-detail"></span></li>
            <li data-id="routing"  class="wgx-step wgx-pending"><span class="wgx-icon"></span><span class="wgx-label">System Routing and Gateway Rebuilds</span><span class="wgx-detail"></span></li>
            <li data-id="firewall" class="wgx-step wgx-pending"><span class="wgx-icon"></span><span class="wgx-label">Global Firewall Reload</span><span class="wgx-detail"></span></li>
        </ol>
        <div id="wgxOverlayFooter" style="margin-top:16px;font-size:12px;opacity:0.6;text-align:center;">Live progress from pfSense</div>
    </div>
</div>
<style>
    @keyframes wgxSpin { to { transform: rotate(360deg); } }
    #wgxStepList .wgx-step { display:flex; align-items:center; gap:12px; padding:10px 14px; font-size:14px; border-radius:6px; }
    #wgxStepList .wgx-step + .wgx-step { margin-top:2px; }
    #wgxStepList .wgx-icon { width:20px; height:20px; border-radius:50%; flex-shrink:0; display:inline-flex; align-items:center; justify-content:center; font-size:12px; font-weight:700; }
    #wgxStepList .wgx-label { flex:1; }
    #wgxStepList .wgx-detail { font-size:12px; opacity:0.6; }
    #wgxStepList .wgx-pending { opacity:0.4; }
    #wgxStepList .wgx-pending .wgx-icon { background:transparent; border:2px solid rgba(255,255,255,0.3); }
    #wgxStepList .wgx-running { background:rgba(76,175,80,0.08); opacity:1; }
    #wgxStepList .wgx-running .wgx-icon { border:2px solid rgba(76,175,80,0.3); border-top-color:#4caf50; animation:wgxSpin 0.8s linear infinite; }
    #wgxStepList .wgx-running .wgx-label { color:#8bc34a; font-weight:500; }
    #wgxStepList .wgx-done { opacity:0.85; }
    #wgxStepList .wgx-done .wgx-icon { background:#4caf50; color:#fff; }
    #wgxStepList .wgx-done .wgx-icon::before { content:'\2713'; }
    #wgxStepList .wgx-fail { background:rgba(229,115,115,0.1); opacity:1; }
    #wgxStepList .wgx-fail .wgx-icon { background:#e57373; color:#fff; }
    #wgxStepList .wgx-fail .wgx-icon::before { content:'\2717'; }
</style>
<style>@keyframes wgxSpin{to{transform:rotate(360deg);}}</style>

<script>
(function() {
    // Deploy-in-progress lock: disable the submit and show the overlay so
    // the user can't accidentally trigger a second POST while the first is
    // still running (that second POST is what previously created a
    // duplicate tunnel entry).
    var form = document.getElementById('iform');
    if (form) {
        // Helpers for updating the step list from streamed events.
        function wgxSetStep(id, state, detail) {
            var li = document.querySelector('#wgxStepList li[data-id="' + id + '"]');
            if (!li) {
                // WS-only steps are not in the initial list — append them.
                var wsLabels = {
                    ws:     'WebSocket Server Deployment',
                    commit: 'Final Configuration Commit'
                };
                if (!wsLabels[id]) { return; }
                li = document.createElement('li');
                li.dataset.id = id;
                li.className  = 'wgx-step wgx-pending';
                li.innerHTML  = '<span class="wgx-icon"></span>' +
                                '<span class="wgx-label">' + wsLabels[id] + '</span>' +
                                '<span class="wgx-detail"></span>';
                document.getElementById('wgxStepList').appendChild(li);
            }
            li.classList.remove('wgx-pending', 'wgx-running', 'wgx-done', 'wgx-fail');
            li.classList.add('wgx-' + state);
            if (detail) {
                var d = li.querySelector('.wgx-detail');
                if (d) { d.textContent = detail; }
            }
        }
        function wgxAllDone() {
            var title = document.getElementById('wgxOverlayTitle');
            var hint  = document.getElementById('wgxDeployHint');
            var spin  = document.getElementById('wgxOverlaySpinner');
            if (title) { title.textContent = 'Tunnel deployed'; }
            if (hint)  { hint.textContent  = 'Finishing up\u2026'; }
            if (spin)  {
                spin.style.borderTopColor = '#4caf50';
                spin.style.animation      = 'none';
                spin.innerHTML            = '<div style="width:100%;height:100%;background:#4caf50;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;">\u2713</div>';
            }
        }

        // Parse an SSE stream from a fetch Response and dispatch events.
        async function wgxStreamRead(resp, onEvent) {
            if (!resp.body || !resp.body.getReader) {
                throw new Error('ReadableStream not supported');
            }
            var reader  = resp.body.getReader();
            var decoder = new TextDecoder();
            var buffer  = '';
            while (true) {
                var chunk = await reader.read();
                if (chunk.done) { break; }
                buffer += decoder.decode(chunk.value, { stream: true });
                var events = buffer.split(/\r?\n\r?\n/);
                buffer = events.pop();  // last one is incomplete
                for (var i = 0; i < events.length; i++) {
                    var line = events[i].replace(/^data:\s*/, '');
                    if (!line || line.charAt(0) === ':') { continue; }
                    try { onEvent(JSON.parse(line)); }
                    catch (e) { /* skip malformed chunks */ }
                }
            }
        }

        // Kick off a streaming deploy. Returns a promise that resolves when
        // the server sends the terminal 'done' event, or rejects on error.
        async function wgxStreamingDeploy(formEl) {
            var fd = new FormData(formEl);
            var resp = await fetch(formEl.action || window.location.pathname, {
                method: 'POST', body: fd, credentials: 'same-origin',
                headers: { 'X-WGX-Stream': '1', 'Accept': 'text/event-stream' }
            });
            if (!resp.ok) { throw new Error('HTTP ' + resp.status); }
            return new Promise(function(resolve, reject) {
                var doneMsg = null;
                wgxStreamRead(resp, function(ev) {
                    switch (ev.event) {
                        case 'hello':      break;
                        case 'step_start': wgxSetStep(ev.id, 'running');            break;
                        case 'step_done':  wgxSetStep(ev.id, 'done', ev.detail);    break;
                        case 'step_fail':  wgxSetStep(ev.id, 'fail', ev.detail);    break;
                        case 'fatal':      reject(new Error(ev.message || 'Deploy failed')); break;
                        case 'done':       doneMsg = ev;                             break;
                    }
                }).then(function() {
                    if (doneMsg) { resolve(doneMsg); }
                    else         { reject(new Error('Stream ended without done event')); }
                }).catch(reject);
            });
        }

        // Build the URL to navigate to after a successful streaming deploy.
        function wgxTargetUrl(done) {
            if (done.port_change && done.new_port) {
                return window.location.protocol + '//' + window.location.hostname +
                       ':' + done.new_port + '/vpn_wg_setup.php?deployed=1';
            }
            return 'vpn_wg_setup.php?deployed=1';
        }

        // When the port is changing, we can't just navigate — the new port
        // isn't listening yet. Poll it until it answers, then hop.
        function wgxPollAndHop(target) {
            var attempts = 0, maxAttempts = 120;
            function tick() {
                attempts++;
                if (attempts > maxAttempts) { return; }
                fetch(target, { method: 'GET', mode: 'no-cors', cache: 'no-store',
                                credentials: 'omit', redirect: 'manual' })
                    .then(function()  { window.location.href = target; })
                    .catch(function() { setTimeout(tick, 500); });
            }
            var title = document.getElementById('wgxOverlayTitle');
            var hint  = document.getElementById('wgxDeployHint');
            if (title) { title.textContent = 'Waiting for pfSense on the new port\u2026'; }
            if (hint)  { hint.textContent  = 'The web UI is restarting. You will be redirected automatically.'; }
            setTimeout(tick, 2000);
        }

        form.addEventListener('submit', function(ev) {
            if (form.dataset.wgxSubmitted === '1') { ev.preventDefault(); return; }
            form.dataset.wgxSubmitted = '1';
            var btn = form.querySelector('button[name="deploy_all"]');
            // CRITICAL: disabling the button inside the submit handler causes
            // the browser to omit its name/value from the POST body (disabled
            // controls aren't submitted) — which meant $_POST['deploy_all']
            // was never set and the whole PHP deploy block was skipped.
            // Preserve the button's contribution via a hidden input, THEN
            // defer the visual disable to the next tick so it doesn't race
            // the form serialization.
            if (btn && !form.querySelector('input[name="deploy_all"]')) {
                var keep = document.createElement('input');
                keep.type  = 'hidden';
                keep.name  = 'deploy_all';
                keep.value = btn.value || 'Deploy';
                form.appendChild(keep);
            }
            if (btn) {
                btn.innerHTML = '<i class="fa fa-spinner fa-spin icon-embed-btn"></i> Deploying…';
                setTimeout(function() { btn.disabled = true; }, 0);
            }
            var ov = document.getElementById('wgxDeployOverlay');
            if (ov) { ov.style.display = 'block'; }

            // Try streaming first. If the browser can't do fetch+streams,
            // or the server doesn't hold up its end, fall back to the
            // plain form submit (which is what would have happened without
            // this JS at all).
            var canStream = typeof fetch === 'function' &&
                            typeof ReadableStream === 'function' &&
                            typeof TextDecoder === 'function';
            if (canStream) {
                ev.preventDefault();
                wgxStreamingDeploy(form).then(function(done) {
                    wgxAllDone();
                    var target = wgxTargetUrl(done);
                    if (done.port_change) { wgxPollAndHop(target); }
                    else                  { setTimeout(function() { window.location.href = target; }, 350); }
                }).catch(function(err) {
                    // Something went wrong mid-stream. Show the error and
                    // stop — the deploy may or may not have completed on
                    // the server side, so re-submitting is unsafe.
                    var title = document.getElementById('wgxOverlayTitle');
                    var hint  = document.getElementById('wgxDeployHint');
                    if (title) { title.textContent = 'Deploy stream interrupted'; }
                    if (hint)  { hint.textContent  = (err && err.message ? err.message : String(err)) +
                        ' — refresh the page to check the tunnel list before retrying.'; }
                });
            }
            // else: fall through, browser will submit the form normally
            var hint = document.getElementById('wgxDeployHint');
            var wsOn = document.getElementById('wsEnabledCheck');
            if (hint && wsOn && wsOn.checked) {
                hint.textContent = 'WebSocket deploy also moves the web UI off port 443. ' +
                    'If the browser prompts about a new certificate after this, that is normal.';
            }
        });
    }

    var wsCheck = document.getElementById('wsEnabledCheck');
    var portEl = document.getElementById('wg_port');
    var notice = document.getElementById('wg_port_ws_notice');
    var helpEl = document.getElementById('wg_port_help');

    if (!wsCheck || !portEl) return;

    wsCheck.addEventListener('change', function() {
        if (this.checked) {
            // Show the notice explaining peers connect via TCP 443
            notice.style.display = '';
    helpEl.style.display = 'none';
        } else {
            notice.style.display = 'none';
    helpEl.style.display = '';
        }
    });
})();
</script>

<?php include("foot.inc"); ?>
