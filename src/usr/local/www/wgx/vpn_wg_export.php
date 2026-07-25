<?php
/**
 * vpn_wg_export.php
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

// === 3.A. Setup & Auth ===
require_once "guiconfig.inc";
require_once "util.inc";
require_once "filter.inc";
require_once "pkg-utils.inc";

// === 3.B. Constants & Binary Discovery ===
define("WGX_VERSION", "1.1.0");
// Probe-verified discovery (see wgx_find_wg_bin below): some pfSense Plus
// builds ship a `wg` at a base path that is NOT wireguard-tools and answers
// "Config file not specified" instead of keys, so candidates are only
// accepted after passing a live genkey test. Key generation itself no
// longer strictly needs the binary (sodium fallback), but `wg set`/`show`
// operations still do.
$wg_bin = wgx_find_wg_bin();

// === 3.C. Settings Engine ===
function wgx_load_settings()
{
    $settings = config_get_path("installedpackages/wgexport/config/0");
    if (is_array($settings)) {
        if (!isset($settings["fallback_subnets"])) {
            $settings["fallback_subnets"] = "192.168.101.0/24";
        }

        // --- NEW GLOBAL DEFAULTS ---
        if (!isset($settings["default_dns"])) {
            $settings["default_dns"] = "8.8.8.8, 8.8.4.4";
        }
        if (!isset($settings["default_ka"])) {
            $settings["default_ka"] = "25";
        }
        if (!isset($settings["default_tier"])) {
            $settings["default_tier"] = "admin";
        }
        if (!isset($settings["key_rotation_days"])) {
            $settings["key_rotation_days"] = "90";
        }
        if (!isset($settings["enable_geo"])) {
            $settings["enable_geo"] = "false";
        }
        if (!isset($settings["webhook_url"])) {
            $settings["webhook_url"] = "";
        }
        if (!isset($settings["webhook_events"])) {
            $settings["webhook_events"] = "expiry,rotation,quota";
        }
        // ---------------------------

        return $settings;
    }
    return [
        "enforce_psk"     => "false",
        "fallback_subnets"=> "192.168.101.0/24",
        "default_dns"     => "8.8.8.8, 8.8.4.4",
        "default_ka"      => "25",
        "default_tier"    => "admin",
        "key_rotation_days" => "90",
        "enable_geo"      => "false",
        "webhook_url"     => "",
        "webhook_events"  => "expiry,rotation,quota",
    ];
}

function wgx_save_settings($settings)
{
    config_set_path("installedpackages/wgexport/config", [$settings]);
    write_config("WG Suite: Saved Global Settings");
}

/**
 * Send a webhook notification to the configured URL.
 * Supports ntfy.sh (topic URL), Slack-compatible payloads, and raw POST.
 *
 * @param string $event   Event type: 'expiry', 'rotation', 'quota', 'peer_add'
 * @param string $message Human-readable message
 * @param array  $data    Optional extra key/value context
 */
function wgx_send_webhook(string $event, string $message, array $data = []): void
{
    $settings = wgx_load_settings();
    $url = trim($settings["webhook_url"] ?? "");
    if (empty($url)) return;

    // Check if this event type is enabled
    $enabled_events = array_map('trim', explode(',', $settings["webhook_events"] ?? "expiry,rotation,quota"));
    if (!in_array($event, $enabled_events, true)) return;

    // Validate URL
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        syslog(LOG_WARNING, "WG Suite: Invalid webhook URL configured — skipping notification.");
        return;
    }

    // Detect ntfy.sh vs Slack-compatible vs generic
    $is_ntfy  = (strpos($url, 'ntfy.sh') !== false);
    $is_slack = (strpos($url, 'hooks.slack.com') !== false ||
    strpos($url, 'discord.com/api/webhooks') !== false);

    if ($is_ntfy) {
        // ntfy: plain text body, event as tag
        $payload     = $message;
        $content_type = 'text/plain';
        $extra_headers = "X-Title: WG Suite\r\nX-Tags: " . $event . "\r\n";
    } elseif ($is_slack) {
        // Slack / Discord compatible
        $payload      = json_encode(['text' => "[WG Suite] [{$event}] {$message}"]);
        $content_type = 'application/json';
        $extra_headers = '';
    } else {
        // Generic JSON POST
        $payload      = json_encode(array_merge([
            'event'   => $event,
            'message' => $message,
            'time'    => time(),
        ], $data));
        $content_type = 'application/json';
        $extra_headers = '';
    }

    $opts = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-Type: {$content_type}\r\n" .
            "User-Agent: WG-Suite/1.2\r\n" .
            $extra_headers,
            'content' => $payload,
            'timeout' => 5,
            'ignore_errors' => true,
        ],
    ];
    @file_get_contents($url, false, stream_context_create($opts));
}

/**
 * Records a config snapshot for a peer into its history file.
 * Keeps the last 10 snapshots. Stored at /var/db/wgx_history/<pubkey_hash>.json
 *
 * @param string $pubkey  The peer's public key
 * @param string $event   Short label e.g. 'provisioned', 'keys rotated', 'ip changed'
 * @param array  $fields  Key/value pairs of what changed (shown in the timeline)
 */
function wgx_record_config_snapshot(string $pubkey, string $event, array $fields): void
{
    if (empty($pubkey)) return;

    $dir  = '/var/db/wgx_history';
    $file = $dir . '/' . hash('sha256', $pubkey) . '.json';

    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $history = [];
    if (file_exists($file) && is_readable($file)) {
        $history = json_decode(file_get_contents($file), true) ?? [];
    }

    $history[] = [
        'time'   => date('Y-m-d H:i:s'),
        'ts'     => time(),
        'event'  => $event,
        'fields' => $fields,
        'user'   => $_SESSION['Username'] ?? 'system',
    ];

    // Keep last 10 snapshots
    if (count($history) > 10) {
        $history = array_slice($history, -10);
    }

    file_put_contents($file, json_encode($history, JSON_PRETTY_PRINT), LOCK_EX);
}

// === 3.C.5 HA Sync Engine (WGX-native XMLRPC over HTTPS) ===
//
// All HA settings live under installedpackages/wgexport/config/0/ha_sync
// so we can piggyback on the existing settings loader/saver. Each box has
// its own block — nothing about HA sync itself is ever synced.

function wgx_ha_load(): array
{
    $ha = config_get_path('installedpackages/wgexport/config/0/ha_sync', []);
    if (!is_array($ha)) { $ha = []; }
    return array_merge([
        'enabled'           => 'false',
        'remote_ip'         => '',
        'remote_port'       => '443',
        'remote_user'       => 'admin',
        'remote_pass'       => '',       // base64 at rest
        'verify_tls'        => 'true',
        'same_network'      => 'false',
        'sync_wg_package'   => 'true',
        'sync_wgx_settings' => 'true',
        'sync_fw_rules'     => 'true',
        'auto_sync'         => 'true',
        'last_sync'         => 0,
        'last_status'       => '',
        'last_error'        => '',
    ], $ha);
}

function wgx_ha_save(array $ha): void
{
    // Never persist plaintext credentials.
    if (!empty($ha['remote_pass']) && !preg_match('#^[A-Za-z0-9+/=]+$#', $ha['remote_pass'])) {
        $ha['remote_pass'] = base64_encode($ha['remote_pass']);
    }
    config_set_path('installedpackages/wgexport/config/0/ha_sync', $ha);
    write_config('WGX HA Sync: settings updated');
}

function wgx_ha_password(array $ha): string
{
    $p = (string)($ha['remote_pass'] ?? '');
    // base64 decode is safe: if invalid it returns false, we treat as empty.
    $dec = base64_decode($p, true);
    return $dec === false ? '' : $dec;
}

function wgx_ha_is_configured(): bool
{
    $ha = wgx_ha_load();
    return ($ha['enabled'] ?? 'false') === 'true'
        && !empty($ha['remote_ip'])
        && !empty($ha['remote_user'])
        && !empty($ha['remote_pass']);
}

/**
 * Detect whether $remote_ip is in one of this box's local subnets.
 * Used to auto-suggest same-network defaults.
 */
function wgx_ha_is_same_network(string $remote_ip): bool
{
    if (!is_ipaddrv4($remote_ip) && !is_ipaddrv6($remote_ip)) { return false; }
    $ifaces = config_get_path('interfaces', []);
    if (!is_array($ifaces)) { return false; }
    foreach ($ifaces as $if) {
        if (empty($if['ipaddr']) || empty($if['subnet'])) { continue; }
        if (!is_ipaddrv4((string)$if['ipaddr'])) { continue; }
        $cidr = $if['ipaddr'] . '/' . (int)$if['subnet'];
        if (ip_in_subnet($remote_ip, $cidr)) { return true; }
    }
    return false;
}

/**
 * Find the local IP that would be used as source to reach $remote_ip.
 * Falls back to WAN IP, then LAN IP.
 */
function wgx_ha_source_ip(string $remote_ip): string
{
    if (function_exists('get_interface_ip')) {
        // Prefer the interface whose subnet contains the remote.
        foreach (config_get_path('interfaces', []) as $ifkey => $if) {
            if (empty($if['ipaddr']) || empty($if['subnet'])) { continue; }
            if (!is_ipaddrv4((string)$if['ipaddr'])) { continue; }
            $cidr = $if['ipaddr'] . '/' . (int)$if['subnet'];
            if (ip_in_subnet($remote_ip, $cidr)) {
                return (string)$if['ipaddr'];
            }
        }
        // Otherwise WAN.
        $wan = @get_interface_ip('wan');
        if (!empty($wan)) { return $wan; }
        // Then LAN.
        $lan = @get_interface_ip('lan');
        if (!empty($lan)) { return $lan; }
    }
    return '';
}

/**
 * Minimal, hardened XML-RPC client. Sufficient for pfsense.exec_php only.
 * We don't need the full XML-RPC type system — exec_php takes one string
 * argument and returns whatever the executed code echoes, so we send a
 * single <string> and read one <string> back.
 *
 *   $ip       — backup pfSense IP
 *   $port     — HTTPS port (usually 443)
 *   $user     — admin username
 *   $pass     — cleartext password
 *   $php_code — code to run on the backup
 *   $verify_tls — whether to enforce cert verification
 *   $timeout  — seconds
 *
 * Returns: ['ok'=>bool, 'value'=>string|null, 'error'=>string|null,
 *           'http_code'=>int|null]
 */
function wgx_ha_xmlrpc_exec(string $ip, int $port, string $user, string $pass,
                            string $php_code, bool $verify_tls = true,
                            int $timeout = 30): array
{
    // Build the XML-RPC methodCall envelope.
    $arg  = htmlspecialchars($php_code, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $body = "<?xml version=\"1.0\"?>\n"
          . "<methodCall>\n"
          . "  <methodName>pfsense.exec_php</methodName>\n"
          . "  <params><param><value><string>{$arg}</string></value></param></params>\n"
          . "</methodCall>";

    // pfSense's XMLRPC path is /xmlrpc.php. Use HTTPS always.
    $host = strpos($ip, ':') !== false ? "[{$ip}]" : $ip;  // IPv6 in brackets
    $url  = "https://{$host}:{$port}/xmlrpc.php";

    $auth = base64_encode("{$user}:{$pass}");
    $hdrs = [
        "Content-Type: text/xml; charset=utf-8",
        "Authorization: Basic {$auth}",
        "User-Agent: WGX-HASync/1.0",
    ];

    $http_code = 0;
    $raw       = false;
    $err       = null;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST            => true,
            CURLOPT_POSTFIELDS      => $body,
            CURLOPT_HTTPHEADER      => $hdrs,
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_TIMEOUT         => $timeout,
            CURLOPT_CONNECTTIMEOUT  => min($timeout, 10),
            CURLOPT_SSL_VERIFYPEER  => $verify_tls,
            CURLOPT_SSL_VERIFYHOST  => $verify_tls ? 2 : 0,
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_MAXFILESIZE     => 8 * 1024 * 1024,
        ]);
        $raw       = curl_exec($ch);
        $http_code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($raw === false) { $err = curl_error($ch); }
        curl_close($ch);
    } else {
        // Fallback: file_get_contents. Uses OpenSSL's own verification.
        $ctx = stream_context_create([
            'http' => [
                'method'        => 'POST',
                'header'        => implode("\r\n", $hdrs),
                'content'       => $body,
                'timeout'       => $timeout,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer'      => $verify_tls,
                'verify_peer_name' => $verify_tls,
            ],
        ]);
        $raw = @file_get_contents($url, false, $ctx);
        if (isset($http_response_header)) {
            foreach ($http_response_header as $h) {
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) {
                    $http_code = (int)$m[1];
                    break;
                }
            }
        }
        if ($raw === false) { $err = 'file_get_contents failed'; }
    }

    if ($raw === false || $raw === '') {
        return ['ok' => false, 'value' => null,
                'error' => $err ?: 'no response from backup',
                'http_code' => $http_code];
    }
    if ($http_code !== 0 && $http_code !== 200) {
        $hint = $http_code === 401 || $http_code === 403
              ? 'wrong username or password'
              : "HTTP {$http_code} from backup";
        return ['ok' => false, 'value' => null, 'error' => $hint,
                'http_code' => $http_code];
    }

    // Parse the XML-RPC reply. Guard against XXE.
    libxml_use_internal_errors(true);
    $doc = @simplexml_load_string($raw, 'SimpleXMLElement',
                                  LIBXML_NONET | LIBXML_NOENT);
    if (!$doc) {
        return ['ok' => false, 'value' => null,
                'error' => 'malformed XML reply from backup',
                'http_code' => $http_code];
    }
    // Fault?
    if (isset($doc->fault)) {
        $fs = 'XML-RPC fault';
        foreach ($doc->fault->value->struct->member ?? [] as $m) {
            if ((string)$m->name === 'faultString') {
                $fs = (string)$m->value->string;
                break;
            }
        }
        return ['ok' => false, 'value' => null, 'error' => $fs,
                'http_code' => $http_code];
    }
    // Success — one <string> parameter.
    $val = $doc->params->param->value ?? null;
    if ($val !== null) {
        $str = $val->string ?? $val;
        return ['ok' => true, 'value' => (string)$str, 'error' => null,
                'http_code' => $http_code];
    }
    return ['ok' => true, 'value' => '', 'error' => null,
            'http_code' => $http_code];
}

/**
 * Translate a transport-layer error string into something actionable.
 * Curl/OpenSSL surface generic phrases like "Connection timed out"
 * or "unable to get local issuer certificate"; the user needs to know
 * WHICH knob fixes it (port, firewall, TLS toggle, etc.).
 */
function wgx_ha_hint_error(string $err, string $ip, int $port, bool $verify_tls): string
{
    $lo = strtolower($err);
    if (strpos($lo, 'timed out') !== false || strpos($lo, 'timeout') !== false) {
        return "Connection to {$ip}:{$port} timed out. Most likely cause: the backup's"
             . " web UI is not on port {$port}. Confirm the port from the backup's"
             . " URL bar (System > Advanced > Admin Access on the backup) and update"
             . " the port field above. If the port is correct, check the backup's"
             . " WAN firewall allows TCP {$port} inbound from this box.";
    }
    if (strpos($lo, 'refused') !== false) {
        return "Connection to {$ip}:{$port} was refused. The port is closed on the"
             . " backup or nothing is listening there. Check the backup's web-UI port.";
    }
    if (strpos($lo, 'could not resolve') !== false || strpos($lo, 'unknown host') !== false) {
        return "Cannot resolve '{$ip}'. Use an IP address or make sure DNS works from"
             . " this box.";
    }
    if (strpos($lo, 'no route') !== false || strpos($lo, 'network is unreachable') !== false) {
        return "No route to {$ip}. If the backup is remote, this box needs a route"
             . " (usually via WAN). If it's on another subnet, check inter-VLAN routing.";
    }
    if ($verify_tls && (strpos($lo, 'certificate') !== false || strpos($lo, 'ssl') !== false
        || strpos($lo, 'handshake') !== false || strpos($lo, 'unable to get local issuer') !== false)) {
        return "TLS verification failed against {$ip}:{$port}: {$err}. If the backup"
             . " uses pfSense's default self-signed certificate, untick 'Verify backup's"
             . " TLS certificate' above.";
    }
    return $err ?: 'unknown error';
}

/**
 * Quick "are you alive?" probe: run `return "pong";` on the backup and
 * check the reply. Also verifies the backup has the WGX package installed.
 */
function wgx_ha_test_connection(array $ha): array
{
    $steps = [];
    $ip    = (string)$ha['remote_ip'];
    $port  = (int)($ha['remote_port'] ?: 443);
    $user  = (string)$ha['remote_user'];
    $pass  = wgx_ha_password($ha);
    $verify = ($ha['verify_tls'] ?? 'true') === 'true';

    if (empty($ip) || empty($pass)) {
        return ['ok' => false, 'steps' => [[
            'label' => 'Configuration', 'ok' => false,
            'msg'   => 'Backup IP and password are required.']]];
    }

    // Probe 1 — authenticated exec_php echoes a nonce back.
    $nonce = bin2hex(random_bytes(8));
    $probe = wgx_ha_xmlrpc_exec($ip, $port, $user, $pass,
        "$toreturn = 'wgx_pong_' . '{$nonce}';", $verify, 15);
    // $toreturn === 'wgx_pong_XX' is what we want. A stray '1' / '' is what
    // some pfSense builds send back on exec_php when the payload didn't set
    // $toreturn — but our probe now DOES set it, so this is really a legacy
    // safety net.
    $probe_val   = (string)$probe['value'];
    $probe_short = $probe_val === '' ? '<empty response body>'
                 : ($probe_val === '1' ? 'boolean true (pfSense pre-set $toreturn behaviour)'
                 : substr($probe_val, 0, 60));
    $steps[] = [
        'label' => 'XML-RPC authentication',
        'ok'    => $probe['ok'] && $probe_val === "wgx_pong_{$nonce}",
        'msg'   => $probe['ok']
            ? ($probe_val === "wgx_pong_{$nonce}"
                ? "Reachable at https://{$ip}:{$port} — auth OK"
                : "Reached backup at https://{$ip}:{$port} and auth accepted, but the probe reply was: {$probe_short}. "
                  . "This usually means the backup's WGX install doesn't include the \$toreturn fix — upgrade the WGX package on the backup.")
            : wgx_ha_hint_error((string)$probe['error'], $ip, $port, $verify),
    ];
    if (!$steps[0]['ok']) {
        return ['ok' => false, 'steps' => $steps];
    }

    // Probe 2 — is WGX installed on the backup?
    $vercheck = wgx_ha_xmlrpc_exec($ip, $port, $user, $pass,
        "\$toreturn = is_file('/usr/local/www/wgx/vpn_wg_export.php') ? 'yes' : 'no';",
        $verify, 15);
    $steps[] = [
        'label' => 'WG Suite installed on backup',
        'ok'    => $vercheck['ok'] && $vercheck['value'] === 'yes',
        'msg'   => $vercheck['ok']
            ? ($vercheck['value'] === 'yes'
                ? 'WG Suite package present at /usr/local/www/wgx'
                : 'WG Suite package NOT found on backup — install pfSense-pkg-wg-export there first')
            : ($vercheck['error'] ?: 'probe failed'),
    ];

    // Probe 3 — WG kernel available (informational, not a hard fail).
    $wgcheck = wgx_ha_xmlrpc_exec($ip, $port, $user, $pass,
        "\$toreturn = is_executable('/usr/local/bin/wg') || is_executable('/usr/bin/wg') ? 'yes' : 'no';",
        $verify, 10);
    $steps[] = [
        'label' => 'WireGuard binary on backup',
        'ok'    => $wgcheck['ok'] && $wgcheck['value'] === 'yes',
        'msg'   => $wgcheck['ok']
            ? ($wgcheck['value'] === 'yes' ? 'wg tools installed' : 'wg tools missing — install pfSense-pkg-WireGuard on backup')
            : ($wgcheck['error'] ?: 'probe failed'),
    ];

    $all_ok = true;
    foreach ($steps as $s) { if (!$s['ok']) { $all_ok = false; break; } }
    return ['ok' => $all_ok, 'steps' => $steps];
}

/**
 * Build the payload to ship to the backup. Only the sections the user
 * opted into (defaults: all on) are included.
 */
function wgx_ha_build_payload(array $ha): array
{
    $payload = ['ts' => time(), 'source' => 'wgx-ha-sync'];

    if (($ha['sync_wg_package'] ?? 'true') === 'true') {
        $payload['wireguard'] = config_get_path('installedpackages/wireguard', []);
    }
    if (($ha['sync_wgx_settings'] ?? 'true') === 'true') {
        $wgx = config_get_path('installedpackages/wgexport', []);
        // Strip our own ha_sync sub-block — each box has its own.
        if (isset($wgx['config'][0]['ha_sync'])) {
            unset($wgx['config'][0]['ha_sync']);
        }
        $payload['wgexport'] = $wgx;
    }
    if (($ha['sync_fw_rules'] ?? 'true') === 'true') {
        // Only WGX-managed firewall rules. Match on descr prefix; user's own
        // custom rules stay untouched on both boxes.
        $rules = config_get_path('filter/rule', []);
        $wgx_rules = [];
        foreach ((array)$rules as $r) {
            $d = (string)($r['descr'] ?? '');
            if (stripos($d, 'WGX:') === 0 || stripos($d, 'WG Suite') === 0) {
                $wgx_rules[] = $r;
            }
        }
        $payload['wgx_fw_rules'] = $wgx_rules;
    }

    return $payload;
}

/**
 * The PHP body that runs on the BACKUP. Consumes a base64-encoded JSON
 * payload from $GLOBALS['wgx_payload_b64'] which we inject before calling.
 * Returns a JSON-encoded step list describing what happened.
 */
function wgx_ha_remote_apply_code(): string
{
    // Keep this pure PHP-that-runs-on-the-backup. No template variables.
    // Wrap the body in an IIFE so early `return`s work AND the final
    // JSON string ends up in $toreturn — the variable pfSense's
    // pfsense.exec_php serialises into the XMLRPC reply.
    return <<<'PHP'
$toreturn = (function() {
$out = ['steps' => []];
$add = function(string $label, bool $ok, string $msg) use (&$out) {
    $out['steps'][] = ['label' => $label, 'ok' => $ok, 'msg' => $msg];
};

try {
    if (empty($GLOBALS['wgx_payload_b64'])) {
        $add('Payload', false, 'no payload supplied');
        return json_encode($out);
    }
    $json = base64_decode($GLOBALS['wgx_payload_b64'], true);
    if ($json === false) { $add('Payload', false, 'base64 decode failed'); return json_encode($out); }
    $payload = json_decode($json, true);
    if (!is_array($payload)) { $add('Payload', false, 'JSON decode failed'); return json_encode($out); }
    $add('Received payload', true, count($payload) . ' section(s)');

    // 1. Preserve backup's own ha_sync — never sync this.
    $backup_ha = config_get_path('installedpackages/wgexport/config/0/ha_sync');

    // 2. Apply WG package config.
    if (isset($payload['wireguard'])) {
        config_set_path('installedpackages/wireguard', $payload['wireguard']);
        $tcount = count(($payload['wireguard']['tunnels']['item'] ?? []));
        $pcount = count(($payload['wireguard']['peers']['item']   ?? []));
        $add('installedpackages/wireguard', true, "applied {$tcount} tunnel(s), {$pcount} peer(s)");
    }

    // 3. Apply WGX settings (except ha_sync).
    if (isset($payload['wgexport'])) {
        config_set_path('installedpackages/wgexport', $payload['wgexport']);
        if ($backup_ha !== null) {
            config_set_path('installedpackages/wgexport/config/0/ha_sync', $backup_ha);
        }
        $add('installedpackages/wgexport', true, 'applied (kept local ha_sync)');
    }

    // 4. Merge WGX-managed firewall rules — replace any existing WGX rules
    //    with the incoming set, preserving user's own rules.
    if (isset($payload['wgx_fw_rules']) && is_array($payload['wgx_fw_rules'])) {
        $rules = config_get_path('filter/rule', []);
        if (!empty($rules) && !isset($rules[0])) { $rules = [$rules]; }
        $rules = array_values(array_filter((array)$rules, function($r) {
            $d = (string)($r['descr'] ?? '');
            return !(stripos($d, 'WGX:') === 0 || stripos($d, 'WG Suite') === 0);
        }));
        foreach ($payload['wgx_fw_rules'] as $r) { $rules[] = $r; }
        config_set_path('filter/rule', $rules);
        $add('WGX firewall rules', true, count($payload['wgx_fw_rules']) . ' rule(s) synced');
    }

    // 5. Persist.
    write_config('WGX HA Sync: payload from primary');
    $add('write_config()', true, 'config.xml saved');

    // 6. Reload WireGuard subsystem on the backup.
    foreach (['/usr/local/pkg/wireguard/includes/wg.inc',
              '/usr/local/pkg/wireguard/includes/wg_service.inc'] as $inc) {
        if (is_file($inc)) { @include_once $inc; }
    }
    $wg_ok = false;
    if (function_exists('wg_toggle_wireguard')) { @wg_toggle_wireguard(); $wg_ok = true; }
    if (function_exists('wg_tunnel_sync'))       { @wg_tunnel_sync();       $wg_ok = true; }
    elseif (function_exists('wg_resync'))         { @wg_resync();            $wg_ok = true; }
    $add('WireGuard resync', $wg_ok, $wg_ok ? 'kernel state reconciled' : 'no reload function available on backup');

    // 7. Firewall reload.
    if (function_exists('filter_configure')) { @filter_configure(); }
    $add('filter_configure()', true, 'ruleset reloaded');

    $out['ok'] = true;
    return json_encode($out);
} catch (Throwable $e) {
    $out['ok'] = false;
    $out['steps'][] = ['label' => 'Exception', 'ok' => false, 'msg' => $e->getMessage()];
    return json_encode($out);
}
})();
PHP;
}

/**
 * Perform a full sync now. Returns a step list.
 * $manual = true for user-clicked sync; false for automatic post-mutation.
 */
function wgx_ha_do_sync(bool $manual = false): array
{
    $ha = wgx_ha_load();
    if (!wgx_ha_is_configured()) {
        return ['ok' => false, 'steps' => [[
            'label' => 'HA Sync', 'ok' => false,
            'msg'   => 'HA Sync is not configured or disabled.']]];
    }

    $steps = [];
    $steps[] = ['label' => 'Build payload', 'ok' => true, 'msg' => 'reading local config'];
    $payload   = wgx_ha_build_payload($ha);
    $payload_b64 = base64_encode(json_encode($payload));
    $steps[count($steps) - 1]['msg'] = strlen($payload_b64) . ' bytes ready';

    // Wrap the remote apply code so we can inject the payload via $GLOBALS.
    $remote_code = "\$GLOBALS['wgx_payload_b64'] = "
                 . var_export($payload_b64, true) . ";\n"
                 . wgx_ha_remote_apply_code();

    $res = wgx_ha_xmlrpc_exec(
        (string)$ha['remote_ip'],
        (int)($ha['remote_port'] ?: 443),
        (string)$ha['remote_user'],
        wgx_ha_password($ha),
        $remote_code,
        ($ha['verify_tls'] ?? 'true') === 'true',
        60
    );
    if (!$res['ok']) {
        $steps[] = ['label' => 'XML-RPC transport', 'ok' => false,
                    'msg'   => $res['error'] ?: 'unknown transport error'];
        $ha['last_sync']   = time();
        $ha['last_status'] = 'failed';
        $ha['last_error']  = (string)$res['error'];
        wgx_ha_save($ha);
        return ['ok' => false, 'steps' => $steps];
    }
    $steps[] = ['label' => 'XML-RPC transport', 'ok' => true,
                'msg'   => "reached backup ({$res['http_code']} OK)"];

    $remote = json_decode((string)$res['value'], true);
    if (!is_array($remote)) {
        $steps[] = ['label' => 'Backup reply', 'ok' => false,
                    'msg'   => 'malformed remote reply'];
        return ['ok' => false, 'steps' => $steps];
    }
    foreach (($remote['steps'] ?? []) as $s) {
        $steps[] = [
            'label' => 'backup: ' . (string)($s['label'] ?? ''),
            'ok'    => (bool)($s['ok'] ?? false),
            'msg'   => (string)($s['msg'] ?? ''),
        ];
    }

    $all_ok = !empty($remote['ok']);
    foreach ($steps as $s) { if (!$s['ok']) { $all_ok = false; break; } }
    $ha['last_sync']   = time();
    $ha['last_status'] = $all_ok ? 'success' : 'failed';
    $ha['last_error']  = $all_ok ? '' : 'one or more steps failed';
    wgx_ha_save($ha);

    if ($manual) {
        wgx_audit_log('HA sync (manual) — ' . ($all_ok ? 'OK' : 'failed'));
    } else {
        syslog(LOG_NOTICE, 'WGX: automatic HA sync ' . ($all_ok ? 'OK' : 'failed'));
    }
    return ['ok' => $all_ok, 'steps' => $steps];
}

/**
 * Fire-and-forget wrapper used after successful peer mutations. Registers
 * a shutdown hook that flushes the HTTP response first, then runs the
 * sync in the background so the user doesn't wait.
 */
function wgx_ha_maybe_sync(): void
{
    if (!wgx_ha_is_configured()) { return; }
    $ha = wgx_ha_load();
    if (($ha['auto_sync'] ?? 'true') !== 'true') { return; }

    // Coalesce: if already scheduled this request, skip.
    if (!empty($GLOBALS['wgx_ha_scheduled'])) { return; }
    $GLOBALS['wgx_ha_scheduled'] = true;

    register_shutdown_function(function () {
        // Flush the response so the user doesn't wait on us.
        if (function_exists('fastcgi_finish_request')) {
            @fastcgi_finish_request();
        } else {
            @ignore_user_abort(true);
            while (@ob_end_flush()) { /* drain */ }
            @flush();
        }
        try { wgx_ha_do_sync(false); } catch (Throwable $e) {
            syslog(LOG_WARNING, 'WGX: HA auto-sync error: ' . $e->getMessage());
        }
    });
}

// === 3.D. Rate Limiter & Shell ===

function wgx_check_rate_limit()
{
    // Sliding 10-minute window. (Previously a hard per-session-lifetime cap
    // of 30, which permanently locked out long-lived admin sessions.)
    $now = time();
    $hits = is_array($_SESSION["wgx_rl_hits"] ?? null) ? $_SESSION["wgx_rl_hits"] : [];
    $hits = array_values(array_filter($hits, fn($t) => ($now - (int)$t) < 600));
    if (count($hits) >= 30) {
        $_SESSION["wgx_rl_hits"] = $hits;
        return false;
    }
    $hits[] = $now;
    $_SESSION["wgx_rl_hits"] = $hits;
    return true;
}

function wgx_wg_exec($wg_bin, $args, $in = null)
{
    if (empty($wg_bin)) {
        return "";
    }
    $cmd = array_merge([$wg_bin], $args);
    $desc = [
        0 => ["pipe", "r"],
        1 => ["pipe", "w"],
        2 => ["pipe", "w"],
    ];

    $proc = proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) {
        return "";
    }

    if ($in !== null) {
        fwrite($pipes[0], $in);
    }
    fclose($pipes[0]);

    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);

    return trim((string) $out);
}

/**
 * Strict WireGuard key format check: 32 bytes base64 = 43 chars + "=".
 * Applied to EVERY generated or derived key so no binary's error text can
 * ever masquerade as a key (the pfSense+ "Config file not specified" bug).
 */
function wgx_key_valid($key): bool
{
    return is_string($key) && preg_match('/^[A-Za-z0-9+\/]{43}=$/', trim($key)) === 1;
}

/**
 * Locate a WORKING wireguard-tools binary. The official WireGuard package's
 * /usr/local/bin/wg is preferred; base-system paths are fallbacks. Every
 * candidate must pass a live `genkey` probe — on some pfSense Plus builds a
 * different `wg` exists at a base path and prints an error string instead of
 * a key, which previously ended up in the UI's key fields.
 */
function wgx_find_wg_bin(): string
{
    foreach (["/usr/local/bin/wg", "/usr/bin/wg", "/sbin/wg", "/usr/sbin/wg"] as $candidate) {
        if (!is_executable($candidate)) {
            continue;
        }
        if (wgx_key_valid(wgx_wg_exec($candidate, ["genkey"]))) {
            return $candidate;
        }
    }
    return "";
}

/**
 * Generate a WireGuard private key. Tries the wg binary first; falls back to
 * pure PHP — a WireGuard private key is 32 random bytes clamped per
 * Curve25519, identical to what `wg genkey` produces.
 */
function wgx_gen_private(string $wg_bin): string
{
    if ($wg_bin !== "") {
        $priv = trim(wgx_wg_exec($wg_bin, ["genkey"]));
        if (wgx_key_valid($priv)) {
            return $priv;
        }
    }
    $raw = random_bytes(32);
    $raw[0]  = chr(ord($raw[0]) & 248);
    $raw[31] = chr((ord($raw[31]) & 127) | 64);
    return base64_encode($raw);
}

/**
 * Derive the public key for a private key. Tries `wg pubkey` first; falls
 * back to sodium's X25519 scalarmult_base, which is byte-identical to wg's
 * derivation (X25519 clamps the scalar internally). Returns "" on failure.
 */
function wgx_derive_public(string $wg_bin, string $priv): string
{
    $priv = trim($priv);
    if (!wgx_key_valid($priv)) {
        return "";
    }
    if ($wg_bin !== "") {
        $pub = trim(wgx_wg_exec($wg_bin, ["pubkey"], $priv . "\n"));
        if (wgx_key_valid($pub)) {
            return $pub;
        }
    }
    if (function_exists("sodium_crypto_scalarmult_base")) {
        $raw = base64_decode($priv, true);
        if ($raw !== false && strlen($raw) === 32) {
            return base64_encode(sodium_crypto_scalarmult_base($raw));
        }
    }
    return "";
}

/**
 * Generate a preshared key. Tries `wg genpsk`; falls back to 32 random
 * bytes base64 — which is exactly what genpsk is.
 */
function wgx_gen_psk_key(string $wg_bin): string
{
    if ($wg_bin !== "") {
        $psk = trim(wgx_wg_exec($wg_bin, ["genpsk"]));
        if (wgx_key_valid($psk)) {
            return $psk;
        }
    }
    return base64_encode(random_bytes(32));
}

function wgx_gen_keypair($wg_bin)
{
    $priv = wgx_gen_private((string)$wg_bin);
    $pub  = wgx_derive_public((string)$wg_bin, $priv);
    if (!wgx_key_valid($priv) || !wgx_key_valid($pub)) {
        return [];
    }
    return [
        "priv" => $priv,
        "pub" => $pub,
    ];
}

/**
 * Push config changes into the live kernel. wg_resync() only regenerates the
 * .conf files on disk; wg_tunnel_sync() is what actually (re)loads tunnels
 * and peers into the kernel. This mirrors the proven add_peer fix so every
 * mutation path behaves identically.
 *
 * @param array $tun_names Tunnel names to sync (empties/duplicates ignored)
 */
function wgx_kernel_sync(array $tun_names): void
{
    $tuns = array_values(array_unique(array_filter($tun_names)));

    @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
    @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
    @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";

    if (function_exists("wg_toggle_wireguard")) {
        wg_toggle_wireguard();
    }
    if (function_exists("wg_tunnel_sync") && !empty($tuns)) {
        wg_tunnel_sync($tuns, true);
    } elseif (function_exists("wg_resync")) {
        foreach ($tuns as $t) {
            wg_resync($t, true);
        }
        if (function_exists("sync_package")) {
            sync_package("wireguard");
        }
    } elseif (function_exists("setup_wg")) {
        setup_wg();
    }
}

// === 3.E. Config & IP Allocation Helpers ===
/**
 * Returns the username of the currently logged-in pfSense admin.
 * pfSense stores this in $_SESSION["Username"] after guiconfig.inc loads.
 */
function wgx_current_user(): string
{
    if (!empty($_SESSION["Username"])) {
        return $_SESSION["Username"];
    }
    // Fallback: check the pfSense authinfo array
    if (!empty($_SESSION["authinfo"]["username"])) {
        return $_SESSION["authinfo"]["username"];
    }
    return "System";
}

/**
 * Writes an audit event to the WG Suite dedicated audit log.
 * Automatically prepends the current admin username to every entry.
 * More reliable than syslog alone since pfSense routes LOG_NOTICE
 * differently across CE and Plus versions.
 */
function wgx_audit_log(string $msg): void
{
    $log_file = '/var/db/wgx_audit.log';
    $max_size = 5 * 1024 * 1024; // 5 MB — rotate when exceeded
    if (file_exists($log_file) && filesize($log_file) > $max_size) {
        rename($log_file, $log_file . '.1');
    }
    $user = wgx_current_user();
    $line = date('Y-m-d H:i:s') . ' [WG Suite] ' . $user . ' - ' . $msg . "\n";
    file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}

function wgx_get_config_array($type): array
{
    global $config;
    $data = [];
    $type_plural = $type . "s";

    if (
        function_exists("config_get_path") &&
        config_get_path("installedpackages/wireguard/{$type_plural}/item") !==
        null
    ) {
        $data = config_get_path(
            "installedpackages/wireguard/{$type_plural}/item",
            []
        );
    } elseif (
        isset($config["installedpackages"]["wireguard"][$type_plural]) &&
        is_array($config["installedpackages"]["wireguard"][$type_plural])
    ) {
        if (
            isset(
                $config["installedpackages"]["wireguard"][$type_plural]["item"]
            )
        ) {
            $data =
                $config["installedpackages"]["wireguard"][$type_plural]["item"];
        } else {
            $data = $config["installedpackages"]["wireguard"][$type_plural];
        }
    } elseif (
        function_exists("config_get_path") &&
        config_get_path("wireguard/{$type}/item") !== null
    ) {
        $data = config_get_path("wireguard/{$type}/item", []);
    } elseif (
        isset($config["wireguard"][$type]) &&
        is_array($config["wireguard"][$type]) &&
        isset($config["wireguard"][$type]["item"])
    ) {
        $data = $config["wireguard"][$type]["item"];
    }

    if (!is_array($data)) {
        return [];
    }
    if (!empty($data) && !isset($data[0])) {
        $data = [$data];
    }
    return $data;
}

function wgx_valid_tunnel_names()
{
    $tunnels = wgx_get_config_array("tunnel");
    $names = [];
    foreach ($tunnels as $t) {
        if (is_array($t) && isset($t["name"])) {
            $names[] = $t["name"];
        }
    }
    return array_filter($names);
}

/**
 * Builds the launcher scripts, setup assistant, and README for a
 * WireGuard WebSocket peer bundle. Returns an array with keys:
 * start_sh, setup_sh, start_bat, readme.
 */


function wgx_get_ws_tunnels(): array
{
    $ws = [];
    foreach (wgx_get_config_array("tunnel") as $t) {
        if (is_array($t) && !empty($t["wgx_ws"]["enabled"])) {
            $ws[$t["name"]] = $t["wgx_ws"];
        }
    }
    return $ws;
}

/**
 * Returns true if the named tunnel has WebSocket transport enabled.
 */
function wgx_tunnel_is_ws(string $tun_name): bool
{
    return array_key_exists($tun_name, wgx_get_ws_tunnels());
}

// ════════════════════════════════════════════════════════════════════════
// PEER CONNECTIVITY DOCTOR
// Walks a peer through the full connectivity chain — config, kernel, port,
// firewall, NAT, handshake, addressing, MTU — and reports each link with a
// concrete fix. Encodes the protocol/tcp-flags trap and the config-vs-
// kernel peer gap as first-class checks.
// ════════════════════════════════════════════════════════════════════════

/** Shell wrapper so every non-wg exec is stubbable in tests. */
function wgx_doctor_exec(string $cmd): array
{
    $out = [];
    $rc  = 1;
    @exec($cmd, $out, $rc);
    return [(int)$rc, $out];
}

function wgx_doctor_check(string $id, string $title, string $status, string $detail, string $fix = ""): array
{
    return ["id" => $id, "title" => $title, "status" => $status, "detail" => $detail, "fix" => $fix];
}

/** True when a rule's port spec (single or 'a-b' range) covers $port. */
function wgx_doctor_port_match($spec, int $port): bool
{
    $spec = trim((string)$spec);
    if ($spec === "" || strtolower($spec) === "any") { return true; }
    if (strpos($spec, "-") !== false) {
        [$lo, $hi] = array_map("intval", explode("-", $spec, 2));
        return $port >= $lo && $port <= $hi;
    }
    return (int)$spec === $port;
}

function wgx_doctor_run(int $idx, string $wg_bin): array
{
    $a_peers   = wgx_get_config_array("peer");
    $a_tunnels = wgx_get_config_array("tunnel");
    $ifaces    = config_get_path("interfaces", []);

    if (!isset($a_peers[$idx]) || !is_array($a_peers[$idx])) {
        return ["success" => false, "message" => "Peer not found."];
    }

    $peer     = $a_peers[$idx];
    $tun_name = trim((string)($peer["tun"] ?? ""));
    $pub      = trim((string)($peer["publickey"] ?? ""));
    $descr    = (string)($peer["descr"] ?? "(unnamed)");
    $checks   = [];

    // ── 1. peer enabled ─────────────────────────────────────────────────
    if (($peer["enabled"] ?? "yes") !== "yes") {
        $checks[] = wgx_doctor_check("peer_enabled", "Peer enabled", "fail",
            "Peer is disabled in the configuration.",
            "Enable the peer, then save so it is loaded into the kernel.");
    } else {
        $checks[] = wgx_doctor_check("peer_enabled", "Peer enabled", "pass",
            "Peer is enabled in the configuration.");
    }

    // ── 2. tunnel exists / enabled / running ────────────────────────────
    $tun = null;
    foreach ($a_tunnels as $t) {
        if (is_array($t) && ($t["name"] ?? "") === $tun_name) { $tun = $t; break; }
    }
    $tun_running = false;
    if ($tun === null) {
        $checks[] = wgx_doctor_check("tunnel_state", "Tunnel state", "fail",
            "Assigned tunnel '{$tun_name}' does not exist in the configuration.",
            "Reassign the peer to an existing tunnel.");
    } else {
        $running_ifs = preg_split('/\s+/', wgx_wg_exec($wg_bin, ["show", "interfaces"]));
        $tun_running = in_array($tun_name, (array)$running_ifs, true);
        $tun_enabled = (($tun["enabled"] ?? "yes") === "yes");
        if (!$tun_enabled) {
            $checks[] = wgx_doctor_check("tunnel_state", "Tunnel state", "fail",
                "Tunnel {$tun_name} is disabled in the configuration.",
                "Enable the tunnel under VPN > WireGuard > Tunnels.");
        } elseif (!$tun_running) {
            $checks[] = wgx_doctor_check("tunnel_state", "Tunnel state", "fail",
                "Tunnel {$tun_name} is enabled but NOT running in the kernel.",
                "Start/restart the WireGuard service, or save the tunnel to trigger a sync.");
        } else {
            $checks[] = wgx_doctor_check("tunnel_state", "Tunnel state", "pass",
                "Tunnel {$tun_name} is enabled and running.");
        }
    }

    // ── one 'wg show dump' feeds checks 3, 8, 9 and the MTU endpoint ────
    $k_present = false; $k_endpoint = ""; $k_hs = 0; $k_rx = 0; $k_tx = 0;
    if ($tun_running && $pub !== "") {
        $dump = wgx_wg_exec($wg_bin, ["show", $tun_name, "dump"]);
        foreach (explode("\n", $dump) as $line) {
            $f = explode("\t", trim($line));
            if (count($f) >= 8 && $f[0] === $pub) {
                $k_present  = true;
                $k_endpoint = $f[2];
                $k_hs       = (int)$f[4];
                $k_rx       = (int)$f[5];
                $k_tx       = (int)$f[6];
                break;
            }
        }
    }

    // ── 3. peer loaded in kernel ────────────────────────────────────────
    if (!$tun_running) {
        $checks[] = wgx_doctor_check("kernel_peer", "Peer loaded in kernel", "skip",
            "Skipped — tunnel is not running.");
    } elseif ($pub === "") {
        $checks[] = wgx_doctor_check("kernel_peer", "Peer loaded in kernel", "fail",
            "Peer has no public key configured.",
            "Set a valid public key on the peer.");
    } elseif ($k_present) {
        $checks[] = wgx_doctor_check("kernel_peer", "Peer loaded in kernel", "pass",
            "Peer public key is present in the running kernel state.");
    } else {
        $checks[] = wgx_doctor_check("kernel_peer", "Peer loaded in kernel", "fail",
            "Peer exists in the configuration but is NOT loaded in the kernel — " .
            "the classic gap when only the .conf files were rewritten without a tunnel sync.",
            "Run a kernel sync: save the tunnel, or use WG Suite's sync so wg_tunnel_sync loads the peers.");
    }

    // ── 4. UDP listen port bound ────────────────────────────────────────
    $port = (int)($tun["listenport"] ?? 0);
    if ($port <= 0) { $port = 51820; }
    if (!$tun_running) {
        $checks[] = wgx_doctor_check("port_bound", "UDP listen port bound", "skip",
            "Skipped — tunnel is not running.");
    } else {
        [$sk_rc, $sk_out] = wgx_doctor_exec("sockstat -4 -6 -l 2>/dev/null");
        if ($sk_rc !== 0 || empty($sk_out)) {
            [$sk_rc, $sk_out] = wgx_doctor_exec("netstat -an 2>/dev/null");
        }
        $bound = false;
        foreach ((array)$sk_out as $sl) {
            if (stripos($sl, "udp") !== false &&
                (strpos($sl, ":{$port} ") !== false || preg_match('/[:.]' . $port . '(\s|$)/', $sl))) {
                $bound = true;
                break;
            }
        }
        if ($bound) {
            $checks[] = wgx_doctor_check("port_bound", "UDP listen port bound", "pass",
                "A listener is bound on UDP {$port}.");
        } elseif (empty($sk_out)) {
            $checks[] = wgx_doctor_check("port_bound", "UDP listen port bound", "info",
                "Could not verify (sockstat/netstat unavailable).");
        } else {
            $checks[] = wgx_doctor_check("port_bound", "UDP listen port bound", "fail",
                "Nothing is listening on UDP {$port}.",
                "The WireGuard service is not binding the tunnel's port — restart the service and re-check.");
        }
    }

    // ── 5. WAN reachability (pass rule or NAT forward for the port) ─────
    $wan_ok = false; $wan_via = "";
    foreach ((array)config_get_path("filter/rule", []) as $r) {
        if (!is_array($r) || isset($r["disabled"])) { continue; }
        if (($r["type"] ?? "pass") !== "pass") { continue; }
        if (stripos((string)($r["interface"] ?? ""), "wan") === false) { continue; }
        $proto = strtolower((string)($r["protocol"] ?? ""));
        if ($proto !== "" && $proto !== "udp") { continue; }
        $dst = (array)($r["destination"] ?? []);
        if (wgx_doctor_port_match($dst["port"] ?? "", $port)) {
            $wan_ok = true; $wan_via = "WAN pass rule '" . ($r["descr"] ?? "(no description)") . "'";
            break;
        }
    }
    if (!$wan_ok) {
        foreach ((array)config_get_path("nat/rule", []) as $r) {
            if (!is_array($r) || isset($r["disabled"])) { continue; }
            $proto = strtolower((string)($r["protocol"] ?? ""));
            if ($proto !== "" && strpos($proto, "udp") === false) { continue; }
            $dst = (array)($r["destination"] ?? []);
            if (wgx_doctor_port_match($dst["port"] ?? "", $port)) {
                $wan_ok = true; $wan_via = "NAT port forward '" . ($r["descr"] ?? "(no description)") . "'";
                break;
            }
        }
    }
    if ($wan_ok) {
        $checks[] = wgx_doctor_check("wan_rule", "WAN reachability rule", "pass",
            "UDP {$port} is reachable via {$wan_via}.");
    } else {
        $checks[] = wgx_doctor_check("wan_rule", "WAN reachability rule", "fail",
            "No enabled WAN pass rule or NAT forward covers UDP {$port} — internet clients cannot reach the endpoint. (Floating rules are not evaluated by this check.)",
            "Add a WAN pass rule for UDP {$port} under Firewall > Rules > WAN.");
    }

    // ── 6. tunnel pass rule + the protocol/flags trap ────────────────────
    $ifkey = "";
    foreach ((array)$ifaces as $ik => $iv) {
        if (is_array($iv) && ($iv["if"] ?? "") === $tun_name) { $ifkey = (string)$ik; break; }
    }
    $rule_ifs = array_filter([strtolower($ifkey), "wireguard", strtolower($tun_name)]);
    $clean = 0; $issues = []; $matched = 0;
    foreach ((array)config_get_path("filter/rule", []) as $r) {
        if (!is_array($r) || isset($r["disabled"])) { continue; }
        if (($r["type"] ?? "pass") !== "pass") { continue; }
        if (!in_array(strtolower((string)($r["interface"] ?? "")), $rule_ifs, true)) { continue; }
        $matched++;
        $rdesc = (string)($r["descr"] ?? "(no description)");
        $proto = strtolower((string)($r["protocol"] ?? ""));
        $has_tcp_flags = (!empty($r["tcpflags1"]) || !empty($r["tcpflags2"])) && !isset($r["tcpflags_any"]);
        if ($proto === "any") {
            // 'any' as a LITERAL value is the malformed state that caused the
            // v1.2.0 outage — the GUI expresses 'any' by omitting the key.
            $issues[] = "Rule '{$rdesc}': protocol is literally set to 'any'" .
                        ($has_tcp_flags ? " combined with TCP flags — this silently drops ALL non-TCP traffic (the exact bug that broke peer internet access)" : " — pf handles this malformed value unpredictably");
        } elseif ($proto !== "" && $proto !== "tcp" && $has_tcp_flags) {
            $issues[] = "Rule '{$rdesc}': TCP flags on a non-TCP rule silently drop all non-TCP traffic";
        } elseif ($proto === "tcp") {
            $issues[] = "Rule '{$rdesc}': restricted to TCP only — peer UDP/ICMP traffic (DNS, ping) will be dropped";
        } else {
            $clean++;
        }
    }
    if ($matched === 0) {
        $checks[] = wgx_doctor_check("tun_rule", "Tunnel firewall pass rule", "fail",
            "No enabled pass rule found on " . ($ifkey !== "" ? strtoupper($ifkey) : "the WireGuard group") . " — peer traffic is blocked by the default deny.",
            "Add a pass rule on the tunnel interface (or WireGuard group) allowing the tunnel subnet. Leave Protocol unset ('Any') and State Type 'keep state'.");
    } elseif ($clean === 0) {
        $checks[] = wgx_doctor_check("tun_rule", "Tunnel firewall pass rule", "fail",
            implode(". ", $issues) . ".",
            "Remove the Protocol restriction (leave 'Any' by omitting it), clear TCP flags (or set tcpflags_any), and use State Type 'keep state'.");
    } elseif (!empty($issues)) {
        $checks[] = wgx_doctor_check("tun_rule", "Tunnel firewall pass rule", "warn",
            "A clean pass rule exists, but suspect rules are also present: " . implode(". ", $issues) . ".",
            "Review the flagged rules — ordering can still cause the trap rule to match first.");
    } else {
        $checks[] = wgx_doctor_check("tun_rule", "Tunnel firewall pass rule", "pass",
            "{$clean} clean pass rule" . ($clean === 1 ? "" : "s") . " on the tunnel — no protocol/flags traps detected.");
    }

    // ── tunnel subnet (used by NAT + addressing) ─────────────────────────
    $sub_ip = ""; $sub_mask = 0; $sub_is6 = false; $sub_src = "none"; $cidr = "";
    if ($tun !== null) {
        [$sub_ip, $sub_mask, $sub_is6, $sub_src] = wgx_detect_tunnel_subnet($tun, $a_peers, $ifaces);
        if (!$sub_is6 && $sub_ip !== "" && $sub_mask > 0) {
            $mask_long = ($sub_mask === 0) ? 0 : ((-1 << (32 - $sub_mask)) & 0xFFFFFFFF);
            $cidr = long2ip(ip2long($sub_ip) & $mask_long) . "/" . $sub_mask;
        }
    }

    // ── 7. outbound NAT ──────────────────────────────────────────────────
    $nat_mode = strtolower((string)config_get_path("nat/outbound/mode", "automatic"));
    if ($nat_mode === "automatic" || $nat_mode === "hybrid") {
        $checks[] = wgx_doctor_check("outbound_nat", "Outbound NAT", "pass",
            "Outbound NAT mode is '{$nat_mode}' — locally-attached tunnel networks are translated automatically.");
    } elseif ($nat_mode === "disabled") {
        $checks[] = wgx_doctor_check("outbound_nat", "Outbound NAT", "warn",
            "Outbound NAT is disabled — peers will only have internet if upstream routes the tunnel subnet.",
            "Enable automatic/hybrid outbound NAT, or add a manual rule for {$cidr}.");
    } else {
        // manual / advanced
        $nat_hit = false;
        foreach ((array)config_get_path("nat/outbound/rule", []) as $nr) {
            if (!is_array($nr) || isset($nr["disabled"])) { continue; }
            $srcnet = (string)(($nr["source"]["network"] ?? ($nr["source"]["address"] ?? "")));
            if ($srcnet === "any" || ($cidr !== "" && $srcnet === $cidr) ||
                ($sub_ip !== "" && strpos($srcnet, substr($cidr, 0, strrpos($cidr, ".") ?: 0)) === 0 && $srcnet !== "")) {
                if ($srcnet === "any" || $srcnet === $cidr) { $nat_hit = true; break; }
            }
        }
        if ($nat_hit) {
            $checks[] = wgx_doctor_check("outbound_nat", "Outbound NAT", "pass",
                "Manual outbound NAT includes a rule covering {$cidr}.");
        } else {
            $checks[] = wgx_doctor_check("outbound_nat", "Outbound NAT", "fail",
                "Outbound NAT is manual and no enabled rule covers {$cidr} — peers connect but get no internet.",
                "Add a WAN outbound NAT rule with source {$cidr} (Firewall > NAT > Outbound).");
        }
    }

    // ── 8. handshake ─────────────────────────────────────────────────────
    $endpoint_hint = "";
    if ($tun !== null) {
        $endpoint_hint = wgx_best_endpoint($tun) . ":" . $port;
    }
    if (!$tun_running || !$k_present) {
        $checks[] = wgx_doctor_check("handshake", "Handshake", "skip",
            "Skipped — peer is not active in the kernel.");
    } elseif ($k_hs <= 0) {
        $checks[] = wgx_doctor_check("handshake", "Handshake", "fail",
            "The peer has NEVER completed a handshake.",
            "Client never reached us or keys mismatch: verify the client's Endpoint is {$endpoint_hint}, that UDP {$port} is open upstream, and that the client config carries this server's current public key.");
    } elseif (time() - $k_hs < 180) {
        $checks[] = wgx_doctor_check("handshake", "Handshake", "pass",
            "Fresh handshake " . (time() - $k_hs) . "s ago — peer is online.");
    } else {
        $ago = time() - $k_hs;
        $ago_h = $ago >= 3600 ? round($ago / 3600, 1) . "h" : round($ago / 60) . "m";
        $checks[] = wgx_doctor_check("handshake", "Handshake", "warn",
            "Last handshake {$ago_h} ago — the peer is currently offline or roaming.",
            "If the client believes it is connected, its session went stale: toggle the client tunnel; consider PersistentKeepalive=25 for NATed clients.");
    }

    // ── 9. transfer symmetry ─────────────────────────────────────────────
    if (!$k_present || $k_hs <= 0) {
        $checks[] = wgx_doctor_check("transfer", "Traffic flow", "skip",
            "Skipped — no session to analyse.");
    } elseif ($k_rx > 0 && $k_tx === 0) {
        $checks[] = wgx_doctor_check("transfer", "Traffic flow", "warn",
            "Receiving from the peer but sending nothing back — return path is broken.",
            "Classic symptoms of the tunnel pass-rule trap or missing outbound NAT; see those checks above.");
    } elseif ($k_tx > 0 && $k_rx === 0) {
        $checks[] = wgx_doctor_check("transfer", "Traffic flow", "warn",
            "Sending to the peer but receiving nothing — the peer's replies are not arriving.",
            "Check the client-side AllowedIPs and any NAT/firewall in front of the client.");
    } else {
        $checks[] = wgx_doctor_check("transfer", "Traffic flow", "pass",
            "Bidirectional traffic observed (rx " . $k_rx . " B / tx " . $k_tx . " B).");
    }

    // ── 10. addressing sanity ────────────────────────────────────────────
    $peer_v4 = [];
    $al  = (array)($peer["allowedips"] ?? []);
    $raw = $al["row"] ?? ($al["item"] ?? []);
    if (is_array($raw)) {
        $rows = isset($raw["address"]) ? [$raw] : $raw;
        foreach ($rows as $r) {
            if (is_array($r) && !empty($r["address"]) && (int)($r["mask"] ?? 0) === 32 &&
                filter_var($r["address"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $peer_v4[] = $r["address"];
            }
        }
    }
    $addr_issues = [];
    if ($cidr !== "" && !empty($peer_v4)) {
        $mask_long = (-1 << (32 - $sub_mask)) & 0xFFFFFFFF;
        $net_long  = ip2long(explode("/", $cidr)[0]);
        foreach ($peer_v4 as $pip) {
            if ((ip2long($pip) & $mask_long) !== $net_long) {
                $addr_issues[] = "{$pip} is outside the tunnel subnet {$cidr} — traffic to it will not route";
            }
        }
    }
    foreach ($a_peers as $oi => $op) {
        if ($oi === $idx || !is_array($op) || ($op["tun"] ?? "") !== $tun_name) { continue; }
        if ($pub !== "" && ($op["publickey"] ?? "") === $pub) {
            $addr_issues[] = "duplicate public key with peer '" . ($op["descr"] ?? "#{$oi}") . "' — the kernel keeps only one";
        }
        $oal  = (array)($op["allowedips"] ?? []);
        $oraw = $oal["row"] ?? ($oal["item"] ?? []);
        if (is_array($oraw)) {
            $orows = isset($oraw["address"]) ? [$oraw] : $oraw;
            foreach ($orows as $r) {
                if (is_array($r) && !empty($r["address"]) && in_array($r["address"], $peer_v4, true)) {
                    $addr_issues[] = "IP conflict: " . $r["address"] . " is also assigned to peer '" . ($op["descr"] ?? "#{$oi}") . "'";
                }
            }
        }
    }
    if (empty($peer_v4)) {
        $checks[] = wgx_doctor_check("addressing", "Addressing", "warn",
            "Peer has no /32 IPv4 address in Allowed IPs.",
            "Assign the peer a /32 inside {$cidr} so it has a stable tunnel address.");
    } elseif (!empty($addr_issues)) {
        $checks[] = wgx_doctor_check("addressing", "Addressing", "fail",
            implode(". ", $addr_issues) . ".",
            "Resolve the conflicts: every peer needs a unique /32 inside {$cidr} and a unique public key per tunnel.");
    } else {
        $checks[] = wgx_doctor_check("addressing", "Addressing", "pass",
            implode(", ", $peer_v4) . " — inside {$cidr}" . ($sub_src === "peer-inference" ? " (subnet inferred from peers)" : "") . ", no conflicts.");
    }

    // ── 11. MTU path probe ───────────────────────────────────────────────
    $tun_mtu = (int)($tun["mtu"] ?? 0);
    if ($tun_mtu <= 0) { $tun_mtu = 1420; }
    $ep_ip = "";
    if ($k_endpoint !== "" && strtolower($k_endpoint) !== "(none)" && strpos($k_endpoint, "[") === false) {
        $ep_ip = explode(":", $k_endpoint)[0];
        if (!filter_var($ep_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $ep_ip = ""; }
    }
    if ($ep_ip === "") {
        $checks[] = wgx_doctor_check("mtu", "Path MTU probe", "skip",
            "Skipped — no live IPv4 endpoint to probe.");
    } else {
        $path_mtu = 0;
        foreach ([1500, 1492, 1472, 1420] as $cand) {
            $payload = $cand - 28;
            [$prc, ] = wgx_doctor_exec("/sbin/ping -D -c 1 -s {$payload} -t 2 " . escapeshellarg($ep_ip) . " >/dev/null 2>&1");
            if ($prc === 0) { $path_mtu = $cand; break; }
        }
        if ($path_mtu === 0) {
            $checks[] = wgx_doctor_check("mtu", "Path MTU probe", "info",
                "Endpoint {$ep_ip} did not answer ICMP probes — inconclusive (many clients/networks block ping).");
        } else {
            $need = $tun_mtu + 60; // IPv4 20 + UDP 8 + WG 32
            if ($path_mtu >= $need) {
                $checks[] = wgx_doctor_check("mtu", "Path MTU probe", "pass",
                    "Path MTU to {$ep_ip} is at least {$path_mtu} — comfortably carries tunnel MTU {$tun_mtu} + 60 overhead.");
            } else {
                $sug_mtu = $path_mtu - 60;
                $sug_mss = $path_mtu - 100;
                $checks[] = wgx_doctor_check("mtu", "Path MTU probe", "warn",
                    "Path MTU {$path_mtu} is below tunnel MTU {$tun_mtu} + 60 overhead — large packets will blackhole (pages half-load, SSH hangs).",
                    "Lower the tunnel MTU to {$sug_mtu} and set MSS clamping to {$sug_mss} on the tunnel interface.");
            }
        }
    }

    // ── 12. WS listener (WS tunnels only) ───────────────────────────────
    $ws_tuns = wgx_get_ws_tunnels();
    if (array_key_exists($tun_name, $ws_tuns)) {
        $ws_port = (int)($ws_tuns[$tun_name]["remote_port"] ?? 443);
        [$wk_rc, $wk_out] = wgx_doctor_exec("sockstat -4 -6 -l 2>/dev/null");
        $ws_bound = false;
        foreach ((array)$wk_out as $wl) {
            if (stripos($wl, "tcp") !== false && preg_match('/[:.]' . $ws_port . '(\s|$)/', $wl)) {
                $ws_bound = true;
                break;
            }
        }
        if ($ws_bound) {
            $checks[] = wgx_doctor_check("ws_listener", "WebSocket transport", "pass",
                "TCP {$ws_port} has a local listener for the WS tunnel.");
        } else {
            $checks[] = wgx_doctor_check("ws_listener", "WebSocket transport", "warn",
                "No local TCP listener on {$ws_port} — fine if a proxy/relay terminates WS in front, otherwise WS clients cannot connect.",
                "Check that wg_ws_server is running, or verify the fronting proxy forwards TCP {$ws_port}.");
        }
    }

    // ── summary ──────────────────────────────────────────────────────────
    $summary = ["pass" => 0, "warn" => 0, "fail" => 0, "info" => 0, "skip" => 0];
    $next = "";
    foreach ($checks as $c) {
        $summary[$c["status"]] = ($summary[$c["status"]] ?? 0) + 1;
        if ($next === "" && $c["status"] === "fail" && $c["fix"] !== "") { $next = $c["fix"]; }
    }
    if ($next === "") {
        foreach ($checks as $c) {
            if ($c["status"] === "warn" && $c["fix"] !== "") { $next = $c["fix"]; break; }
        }
    }
    if ($next === "") { $next = "All checks passed — the chain from client to internet looks healthy."; }

    return [
        "success"     => true,
        "peer"        => $descr,
        "tun"         => $tun_name,
        "checks"      => $checks,
        "summary"     => $summary,
        "next_action" => $next,
    ];
}

function wgx_best_endpoint($server_tun = null)
{
    global $config;
    if (
        isset($config["dyndnses"]["dyndns"]) &&
        is_array($config["dyndnses"]["dyndns"])
    ) {
        foreach ($config["dyndnses"]["dyndns"] as $ddns) {
            if (is_array($ddns) && !empty($ddns["host"])) {
                return trim($ddns["host"]);
            }
        }
    }

    return (string) get_interface_ip("wan");
}


/**
 * Convert a host IP and CIDR prefix into the network address in CIDR notation.
 * e.g. wgx_cidr_network("192.168.101.50", 24) => "192.168.101.0/24"
 */
function wgx_cidr_network(string $ip, int $prefix): string
{
    $ip_long = ip2long($ip);
    if ($ip_long === false) {
        return $ip . "/" . $prefix;
    }
    $mask_long = $prefix === 0 ? 0 : (~((1 << (32 - $prefix)) - 1)) & 0xFFFFFFFF;
    $net_long  = $ip_long & $mask_long;
    return long2ip($net_long) . "/" . $prefix;
}

function wgx_get_local_subnets()
{
    $settings = wgx_load_settings();
    $subnets = [];

    $ifaces = config_get_path("interfaces", []);
    if (is_array($ifaces)) {
        foreach ($ifaces as $iface) {
            if (
                isset($iface["ipaddr"]) &&
                is_ipaddrv4($iface["ipaddr"]) &&
                isset($iface["subnet"])
            ) {
                $sub = gen_subnet($iface["ipaddr"], $iface["subnet"]);
                $subnets[] = "{$sub}/{$iface["subnet"]}";
            }
        }
    }

    if (empty($subnets)) {
        return $settings["fallback_subnets"];
    } else {
        return implode(", ", $subnets);
    }
}

function wgx_build_conf_template($peer, $server_tun)
{
    $lines = [];
    $lines[] = "[Interface]";
    $lines[] = "PrivateKey = __PRIVATE_KEY_PLACEHOLDER__";

    $ips = [];
    $allowedips =
        isset($peer["allowedips"]) && is_array($peer["allowedips"])
        ? $peer["allowedips"]
        : [];
    $raw_rows = $allowedips["row"] ?? ($allowedips["item"] ?? []);

    if (is_array($raw_rows)) {
        if (isset($raw_rows["address"])) {
            $rows = [$raw_rows];
        } else {
            $rows = $raw_rows;
        }
        foreach ($rows as $row) {
            if (is_array($row) && !empty($row["address"])) {
                $mask = !empty($row["mask"]) ? "/" . (int) $row["mask"] : "/32";
                $ips[] = $row["address"] . $mask;
            }
        }
    }

    $lines[] =
        "Address = " . (!empty($ips) ? implode(", ", $ips) : "10.x.x.x/32");
    $lines[] = "__DNS_PLACEHOLDER__";
    $lines[] =
        "MTU = " . (!empty($server_tun["mtu"]) ? $server_tun["mtu"] : "1420");

    $lines[] = "";
    $lines[] = "[Peer]";
    $lines[] =
        "PublicKey = " .
        htmlspecialchars_decode(
            is_array($server_tun) && isset($server_tun["publickey"])
                ? $server_tun["publickey"]
                : "",
            ENT_QUOTES
        );
    $lines[] = "__PSK_PLACEHOLDER__";
    $lines[] = "Endpoint = __ENDPOINT_PLACEHOLDER__";
    $lines[] = "AllowedIPs = __ALLOWEDIPS_PLACEHOLDER__";
    $lines[] = "PersistentKeepalive = __KEEPALIVE_PLACEHOLDER__";

    return implode("\n", $lines) . "\n";
}

/**
 * Given a tunnel config entry, this box's peer list and pfSense's live
 * $config['interfaces'] block, work out what subnet the tunnel is on so
 * the Assigned-IP auto-picker can offer a sensible next free address.
 *
 * Returns an array:
 *   [ base_ip, mask, is_ipv6, source ]
 * where 'source' is a human-friendly tag ("iface", "tun.addresses",
 * "peer-inference", "default") for diagnostics. On complete failure the
 * base_ip is "" and every other field is safe to interpolate.
 *
 * Detection priority — first match wins:
 *   1. The pfSense OPT interface whose 'if' equals this tunnel name
 *      AND carries a valid IPv4/IPv6 ipaddr + subnet. This wins because
 *      the interface's declared subnet is authoritative.
 *   2. The tunnel's own 'addresses'/'row' or 'addresses'/'item' block,
 *      handling every serialization shape we've seen pfSense emit
 *      (list-of-dicts / single-flattened-dict / numeric-key-only-dict).
 *      Prefers IPv4 unless the tunnel is IPv6-only.
 *   3. Peer inference: if any existing peer on this tunnel has an
 *      allowedips entry that looks like a /32 (or IPv6 /128), the /24
 *      containing it is a very good guess for the tunnel's subnet, and
 *      the tunnel address is (network-address + 1).
 *   4. A safe default so the field is never empty on a brand-new install
 *      (10.10.10.0/24) — the user can always overwrite it.
 */
function wgx_detect_tunnel_subnet(array $tun, array $peers, array $ifaces): array
{
    $tun_name = (string)($tun['name'] ?? '');

    // ── 1. OPT interface with a real address on it ──────────────────────────
    foreach ($ifaces as $iface) {
        if (!is_array($iface)) { continue; }
        if (($iface['if'] ?? '') !== $tun_name) { continue; }
        $ip   = (string)($iface['ipaddr'] ?? '');
        $mask = (int)($iface['subnet'] ?? 0);
        if ($ip !== '' && is_ipaddrv4($ip) && $mask >= 8 && $mask <= 32) {
            return [$ip, $mask, false, 'iface'];
        }
        $ip6   = (string)($iface['ipaddrv6'] ?? '');
        $mask6 = (int)($iface['subnetv6'] ?? 0);
        if ($ip6 !== '' && is_ipaddrv6($ip6) && $mask6 >= 8 && $mask6 <= 128) {
            return [$ip6, $mask6, true, 'iface'];
        }
    }

    // ── 2. tun/addresses in every shape pfSense's XML deserializer produces ─
    // Try both 'row' and 'item'; then collect every {address, mask} entry no
    // matter whether they arrived as a list, a single flattened dict, or a
    // numeric-keyed assoc-array.
    $addrs = (array)($tun['addresses'] ?? []);
    foreach (['row', 'item'] as $bucket) {
        if (!isset($addrs[$bucket])) { continue; }
        $node = $addrs[$bucket];
        if (!is_array($node)) { continue; }

        // Normalise into a list of rows.
        $rows = [];
        if (isset($node['address'])) {
            // Single flattened dict.
            $rows[] = $node;
        } else {
            // List — either sequential or numeric-keyed.
            foreach ($node as $row) {
                if (is_array($row) && isset($row['address'])) { $rows[] = $row; }
            }
        }

        // Prefer the first IPv4 entry; fall back to the first IPv6.
        $v4 = null; $v6 = null;
        foreach ($rows as $r) {
            $a = (string)$r['address'];
            $m = (int)($r['mask'] ?? 24);
            if (is_ipaddrv4($a) && $v4 === null) { $v4 = [$a, $m > 0 ? $m : 24]; }
            elseif (is_ipaddrv6($a) && $v6 === null) { $v6 = [$a, $m > 0 ? $m : 64]; }
        }
        if ($v4 !== null) { return [$v4[0], $v4[1], false, 'tun.addresses']; }
        if ($v6 !== null) { return [$v6[0], $v6[1], true,  'tun.addresses']; }
    }

    // ── 2b. Legacy single-field variants some pfSense builds emit ───────────
    foreach (['address', 'tun_addr', 'tun_address'] as $k) {
        $v = trim((string)($tun[$k] ?? ''));
        if ($v === '') { continue; }
        // Accept "10.10.10.1/24" or "10.10.10.1"
        $parts = explode('/', $v, 2);
        $ip    = $parts[0];
        $mask  = isset($parts[1]) ? (int)$parts[1] : 0;
        if (is_ipaddrv4($ip)) { return [$ip, $mask > 0 ? $mask : 24, false, 'tun.'.$k]; }
        if (is_ipaddrv6($ip)) { return [$ip, $mask > 0 ? $mask : 64, true,  'tun.'.$k]; }
    }

    // ── 3. Peer inference ───────────────────────────────────────────────────
    // If existing peers on this tunnel have allowedips, we can guess the
    // subnet from them. A /32 peer at 10.10.10.7 → tunnel is almost
    // certainly 10.10.10.1/24. Not authoritative but a good default so the
    // field auto-fills instead of staying blank.
    $peer_v4 = []; $peer_v6 = [];
    foreach ($peers as $p) {
        if (!is_array($p) || ($p['tun'] ?? '') !== $tun_name) { continue; }
        $al = (array)($p['allowedips'] ?? []);
        $raw = $al['row'] ?? ($al['item'] ?? []);
        if (!is_array($raw)) { continue; }
        $rows = isset($raw['address']) ? [$raw] : $raw;
        foreach ($rows as $r) {
            if (!is_array($r) || empty($r['address'])) { continue; }
            $a = (string)$r['address'];
            if (is_ipaddrv4($a)) { $peer_v4[] = $a; }
            elseif (is_ipaddrv6($a)) { $peer_v6[] = $a; }
        }
    }
    if (!empty($peer_v4)) {
        // Take the smallest peer address, drop last octet, use x.x.x.1 as base.
        sort($peer_v4, SORT_NUMERIC);
        $first  = $peer_v4[0];
        $octets = explode('.', $first);
        $octets[3] = '1';
        $guess  = implode('.', $octets);
        return [$guess, 24, false, 'peer-inference'];
    }
    if (!empty($peer_v6)) {
        // For IPv6 there are so many shapes that /64 with the first host
        // address is the honest default; users can override.
        $first = $peer_v6[0];
        $bin   = @inet_pton($first);
        if ($bin !== false && strlen($bin) === 16) {
            // Zero the interface identifier and set ::1.
            $bin = substr($bin, 0, 8) . str_repeat("\x00", 7) . "\x01";
            $guess = inet_ntop($bin);
            if ($guess !== false) { return [$guess, 64, true, 'peer-inference']; }
        }
    }

    // ── 4. Nothing to go on. Return a sensible neutral default so the
    //      field isn't empty on a fresh box; the user can override.
    return ['10.10.10.1', 24, false, 'default'];
}

function wgx_allocate_ipv4($tun_name, $tun_base_ip, $tun_mask)
{
    global $config;
    if (!is_ipaddrv4($tun_base_ip)) {
        return null;
    }
    $mask = (int) $tun_mask;
    $net_long = ip2long(gen_subnet($tun_base_ip, $mask));
    $host_bits = 32 - $mask;
    $bcast_long = $net_long + (1 << $host_bits) - 1;

    $used = [];
    $used[ip2long($tun_base_ip)] = true;

    foreach (wgx_get_config_array("peer") as $p) {
        if (!is_array($p) || ($p["tun"] ?? "") !== $tun_name) {
            continue;
        }
        $allowedips =
            isset($p["allowedips"]) && is_array($p["allowedips"])
            ? $p["allowedips"]
            : [];
        $raw = $allowedips["row"] ?? ($allowedips["item"] ?? []);
        if (!is_array($raw)) {
            continue;
        }
        $rows = isset($raw["address"]) ? [$raw] : $raw;
        foreach ($rows as $row) {
            if (
                is_array($row) &&
                !empty($row["address"]) &&
                is_ipaddrv4($row["address"])
            ) {
                $used[ip2long($row["address"])] = true;
            }
        }
    }

    for ($candidate = $net_long + 2; $candidate < $bcast_long; $candidate++) {
        if (!isset($used[$candidate])) {
            return long2ip($candidate) . "/32";
        }
    }
    return null;
}

function wgx_allocate_ipv6($tun_name, $tun_base_ip, $prefix_len)
{
    global $config;
    if (!is_ipaddrv6($tun_base_ip)) {
        return null;
    }
    $used = [$tun_base_ip => true];

    foreach (wgx_get_config_array("peer") as $p) {
        if (!is_array($p) || ($p["tun"] ?? "") !== $tun_name) {
            continue;
        }
        $allowedips =
            isset($p["allowedips"]) && is_array($p["allowedips"])
            ? $p["allowedips"]
            : [];
        $raw = $allowedips["row"] ?? ($allowedips["item"] ?? []);
        if (!is_array($raw)) {
            continue;
        }
        $rows = isset($raw["address"]) ? [$raw] : $raw;
        foreach ($rows as $row) {
            if (
                is_array($row) &&
                !empty($row["address"]) &&
                is_ipaddrv6($row["address"])
            ) {
                $used[$row["address"]] = true;
            }
        }
    }

    $base_bin = inet_pton($tun_base_ip);
    if ($base_bin === false) {
        return null;
    }
    $net_bin = $base_bin;
    for ($bit = (int) $prefix_len; $bit < 128; $bit++) {
        $b = (int) ($bit / 8);
        $net_bin[$b] = chr(ord($net_bin[$b]) & ~(1 << 7 - ($bit % 8)));
    }

    for ($i = 2; $i <= 65534; $i++) {
        $candidate_bin = $net_bin;
        $candidate_bin[14] = chr(($i >> 8) & 0xff);
        $candidate_bin[15] = chr($i & 0xff);
        $candidate = inet_ntop($candidate_bin);
        if ($candidate !== false && !isset($used[$candidate])) {
            return $candidate . "/" . $prefix_len;
        }
    }
    return null;
}

function wgx_check_ip_conflicts($tun_name, array $proposed_ips)
{
    $conflicts = [];
    foreach (wgx_get_config_array("peer") as $p) {
        if (!is_array($p) || ($p["tun"] ?? "") !== $tun_name) {
            continue;
        }
        $allowedips =
            isset($p["allowedips"]) && is_array($p["allowedips"])
            ? $p["allowedips"]
            : [];
        $raw = $allowedips["row"] ?? ($allowedips["item"] ?? []);
        if (!is_array($raw)) {
            continue;
        }
        $rows = isset($raw["address"]) ? [$raw] : $raw;
        foreach ($rows as $existing) {
            if (!is_array($existing) || empty($existing["address"])) {
                continue;
            }
            foreach ($proposed_ips as $prop) {
                if (($prop["address"] ?? "") === $existing["address"]) {
                    $conflicts[] = sprintf(
                        '%s/%s is already assigned to peer "%s"',
                        $existing["address"],
                        $existing["mask"] ?? "32",
                        htmlspecialchars(
                            $p["descr"] ?? "unknown",
                            ENT_QUOTES,
                            "UTF-8"
                        )
                    );
                }
            }
        }
    }
    return $conflicts;
}

// === 3.F. CLI Background Worker (Cron Auto-Rotation) ===
if (php_sapi_name() === "cli" || empty($_SERVER["REMOTE_ADDR"])) {
    global $argv;
    if (isset($argv[1]) && $argv[1] === "cron_rotate") {
        $a_peers = wgx_get_config_array("peer");
        $changed = false;
        foreach ($a_peers as $idx => &$p) {
            if (
                !empty($p["wgx_autorotate"]) &&
                (int) $p["wgx_autorotate"] > 0
            ) {
                $created = (int) ($p["key_created"] ?? time());
                $interval_seconds = (int) $p["wgx_autorotate"] * 86400;
                $time_until_rotation = ($created + $interval_seconds) - time();

                // Rotation warning — send once when within 7 days of scheduled rotation
                if ($time_until_rotation > 0 && $time_until_rotation <= 604800 && empty($p["wgx_rotation_warned"])) {
                    $p["wgx_rotation_warned"] = "1";
                    $changed = true;
                    $warn_days = max(1, (int)round($time_until_rotation / 86400));
                    syslog(LOG_NOTICE, "WG Suite: Key rotation due in {$warn_days} day(s) for peer '{$p["descr"]}'");
                    if (!function_exists('send_smtp_message')) {
                        @include_once('/etc/inc/notify.inc');
                    }
                    if (function_exists('send_smtp_message') &&
                        !empty(config_get_path('notifications/smtp/ipaddress'))) {
                        @send_smtp_message(
                            "WG Suite Automated Notice\n\nKey rotation is due in approximately {$warn_days} day(s) for peer '{$p["descr"]}'.\n\nWG Suite will rotate the keys automatically on the scheduled date. The peer will receive a new configuration — ensure they are set up to receive updates.\n",
                                           "WG Suite: Key rotation due soon for '{$p["descr"]}'"
                        );
                        }
                }

                if (time() - $created >= $interval_seconds) {
                    $pair = wgx_gen_keypair($wg_bin);
                    if (!empty($pair["pub"])) {
                        $p["publickey"] = $pair["pub"];
                        $p["privatekey"] = $pair["priv"];
                        $p["key_created"] = time();
                        unset($p["wgx_rotation_warned"]); // reset for next cycle
                        $changed = true;
                        wgx_record_config_snapshot($pair["pub"], 'Auto-rotate', [
                            'tunnel'     => $p["tun"] ?? '',
                            'new_pubkey' => substr($pair["pub"], 0, 12) . '…',
                        ]);
                        syslog(
                            LOG_NOTICE,
                            "WGX Auto-Rotate: Rotated keys for peer {$p["descr"]}"
                        );
                    }
                }
            }
        }
        if ($changed) {
            global $config;
            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }
            write_config("WG Suite: Scheduled Auto-Rotation of Peer Keys");
            sync_package("wireguard");
            @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";
            if (function_exists("setup_wg")) {
                setup_wg();
            }
        }
        exit(0);
    }
}

// =========================================================================
// 4.0 AJAX HANDLERS (POST / GET API)
// =========================================================================

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["action"])) {
    // Buffer output from here so all handlers can safely call header()
    ob_start();

    // === Standalone: migrate_peer_to_ws ===
    // Moves an existing peer from a standard tunnel to a WebSocket-enabled tunnel.
    // Creates a new peer entry on the WS tunnel with the same keys/IPs, removes the
    // old entry, and returns the updated conf text with the TCP endpoint.
    if (
        $_SERVER["REQUEST_METHOD"] === "POST" &&
        ($_POST["action"] ?? "") === "migrate_peer_to_ws"
    ) {
        if (!csrf_check(false)) {
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "CSRF failed."]);
            exit();
        }

        $src_idx  = (int)($_POST["src_idx"]  ?? -1);
        $dst_tun  = trim($_POST["dst_tun"]   ?? "");

        $a_peers  = wgx_get_config_array("peer");
        $ws_tuns  = wgx_get_ws_tunnels();

        if ($src_idx < 0 || !isset($a_peers[$src_idx])) {
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Peer not found."]);
            exit();
        }
        if (!array_key_exists($dst_tun, $ws_tuns)) {
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Target tunnel is not a WebSocket tunnel."]);
            exit();
        }

        $src_peer = $a_peers[$src_idx];

        // Check the destination tunnel doesn't already have this public key
        foreach ($a_peers as $i => $p) {
            if ($i === $src_idx) continue;
            if (($p["tun"] ?? "") === $dst_tun && ($p["publickey"] ?? "") === ($src_peer["publickey"] ?? "")) {
                header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "Peer already exists on the target WS tunnel."]);
                exit();
            }
        }

        // Build the migrated peer — same as source but on the new tunnel,
        // with wgx_ws_transport flag set so conf export uses TCP endpoint
        $migrated = $src_peer;
        $migrated["tun"]              = $dst_tun;
        $migrated["wgx_ws_transport"] = "1";
        unset($migrated["wgx_ws_override"]); // clear any per-peer override from old tunnel

        // Remove source peer, append migrated peer
        unset($a_peers[$src_idx]);
        $a_peers   = array_values($a_peers);
        $a_peers[] = $migrated;
        $new_idx   = count($a_peers) - 1;

        config_set_path("installedpackages/wireguard/peers/item", $a_peers);
        write_config("WG Suite: Migrated peer '{$src_peer["descr"]}' to WebSocket tunnel {$dst_tun}");
        syslog(LOG_NOTICE, "WG Suite: Peer '{$src_peer["descr"]}' migrated to WS tunnel {$dst_tun}");
        wgx_audit_log("Migrated peer '{$src_peer["descr"]}' to WebSocket tunnel {$dst_tun}");

        // Purge the peer from the old tunnel's kernel state, then fully
        // sync BOTH tunnels so the move takes effect immediately
        // (wg_resync alone only rewrites the .conf files on disk).
        if (!empty($src_peer["tun"]) && !empty($src_peer["publickey"])) {
            wgx_wg_exec($wg_bin, ["set", $src_peer["tun"], "peer", $src_peer["publickey"], "remove"]);
        }
        wgx_kernel_sync([$src_peer["tun"] ?? "", $dst_tun]);

        // Build the new conf with WS endpoint so the admin can send it to the peer
        $a_tunnels = wgx_get_config_array("tunnel");
        $dst_tun_obj = null;
        foreach ($a_tunnels as $t) {
            if (is_array($t) && ($t["name"] ?? "") === $dst_tun) {
                $dst_tun_obj = $t;
                break;
            }
        }
        $ws_cfg     = $ws_tuns[$dst_tun];
        $wan_ip     = wgx_best_endpoint($dst_tun_obj);
        $ws_port    = $ws_cfg["remote_port"] ?? "443";
        $new_endpoint = "{$wan_ip}:{$ws_port}";

        header("Content-Type: application/json");
        echo json_encode([
            "success"      => true,
            "message"      => "Peer migrated to {$dst_tun} (WebSocket). Send the new config to the peer device.",
            "new_idx"      => $new_idx,
            "new_endpoint" => $new_endpoint,
            "new_tun"      => $dst_tun,
        ]);
        exit();
    }

    // === Standalone: save_peer_tags ===
    if (
        $_SERVER["REQUEST_METHOD"] === "POST" &&
        ($_POST["action"] ?? "") === "save_peer_tags"
    ) {
        if (!csrf_check(false)) {
            header("Content-Type: application/json");
            echo json_encode([
                "success" => false,
                "message" => "CSRF validation failed.",
            ]);
            exit();
        }
        $tag_idx = (int) ($_POST["idx"] ?? -1);
        $tag_raw = trim($_POST["tags"] ?? "");
        // Sanitise: strip non-alphanumeric chars except comma, space, hyphen, underscore
        $tag_clean = preg_replace("/[^a-zA-Z0-9,\s_-]/", "", $tag_raw);
        // Normalise: trim each tag, remove empty
        $tag_parts = array_filter(
            array_map("trim", explode(",", $tag_clean)),
            "strlen"
        );
        $tag_str = implode(",", $tag_parts);

        $a_peers_t = wgx_get_config_array("peer");
        if ($tag_idx < 0 || $tag_idx >= count($a_peers_t)) {
            header("Content-Type: application/json");
            echo json_encode([
                "success" => false,
                "message" => "Peer index out of range.",
            ]);
            exit();
        }
        $a_peers_t[$tag_idx]["wgx_tags"] = $tag_str;
        config_set_path("installedpackages/wireguard/peers/item", $a_peers_t);
        write_config("WG Suite: Updated tags for peer index {$tag_idx}");
        syslog(
            LOG_NOTICE,
            "WG Suite: Tags updated for peer index {$tag_idx}: {$tag_str}"
        );
        header("Content-Type: application/json");
        echo json_encode(["success" => true, "tags" => $tag_str]);
        exit();
    }

    ob_start();
    try {
        // === 4.C. POST: derive_pub ===
        if ($_POST["action"] === "derive_pub") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }
            $priv = trim($_POST["privkey"] ?? "");
            if (empty($priv)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Missing private key.",
                ]);
                exit();
            }
            $pub = wgx_derive_public($wg_bin, $priv);
            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            if (!wgx_key_valid($pub)) {
                echo json_encode([
                    "success" => false,
                    "message" => "Could not derive a public key — check the private key format.",
                ]);
                exit();
            }
            echo json_encode(["success" => true, "pub" => $pub]);
            exit();
        }

        // === 4.C2. POST: test_webhook ===
        if ($_POST["action"] === "test_webhook") {
            if (!csrf_check(false)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF validation failed."]);
                exit();
            }
            wgx_send_webhook("expiry", "This is a test notification from WG Suite.", ["test" => true]);
            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode(["success" => true]);
            exit();
        }

        // === 4.D. POST: save_global ===
        if ($_POST["action"] === "save_global") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            $old_settings = wgx_load_settings();
            $settings = [];
            $settings["enforce_psk"] =
                isset($_POST["enforce_psk"]) && $_POST["enforce_psk"] === "true"
                ? "true"
                : "false";
            $settings["fallback_subnets"] = trim(
                $_POST["fallback_subnets"] ?? "192.168.101.0/24"
            );

            // --- NEW VARIABLES ---
            $settings["default_dns"] = trim(
                $_POST["default_dns"] ?? "8.8.8.8, 8.8.4.4"
            );
            $settings["default_ka"] = trim($_POST["default_ka"] ?? "25");
            $settings["key_rotation_days"] = max(
                1,
                (int) ($_POST["key_rotation_days"] ?? 90)
            );
            $settings["default_tier"] = trim($_POST["default_tier"] ?? "admin");
            // Save per-tunnel peer limits directly onto each tunnel config
            $all_tuns_edit = wgx_get_config_array("tunnel");
            $tuns_changed = false;
            foreach ($all_tuns_edit as &$_t) {
                $tn = $_t["name"] ?? "";
                $limit_key = "peer_limit_" . $tn;
                if (isset($_POST[$limit_key])) {
                    $new_limit = max(0, (int)$_POST[$limit_key]);
                    if (($new_limit === 0 && isset($_t["wgx_peer_limit"])) ||
                        (int)($_t["wgx_peer_limit"] ?? 0) !== $new_limit) {
                        $_t["wgx_peer_limit"] = $new_limit > 0 ? (string)$new_limit : "";
                    $tuns_changed = true;
                        }
                }
            }
            unset($_t);
            if ($tuns_changed) {
                if (function_exists("config_set_path")) {
                    config_set_path("installedpackages/wireguard/tunnels/item", $all_tuns_edit);
                } else {
                    $config["installedpackages"]["wireguard"]["tunnels"]["item"] = $all_tuns_edit;
                }
            }

            $settings["auto_cron"] =
            isset($_POST["auto_cron"]) && $_POST["auto_cron"] === "true"
                ? "true"
                : "false";
                $settings["enable_geo"] =
                isset($_POST["enable_geo"]) && $_POST["enable_geo"] === "true"
                ? "true"
                : "false";

                // Webhook notifications
                $settings["webhook_url"] = trim($_POST["webhook_url"] ?? "");
                // Whitelist allowed URL schemes — no file://, data:// etc.
                if (!empty($settings["webhook_url"]) &&
                    !preg_match('#^https?://#i', $settings["webhook_url"])) {
                    $settings["webhook_url"] = "";
                    }
                    $wh_events = [];
                foreach (["expiry", "rotation", "quota", "peer_add"] as $ev) {
                    if (!empty($_POST["webhook_event_" . $ev])) {
                        $wh_events[] = $ev;
                    }
                }
                $settings["webhook_events"] = implode(",", $wh_events) ?: "expiry,rotation,quota";

                // === WebSocket Transport global defaults ===
            $settings["ws_default_remote_port"] = (int)($_POST["ws_default_remote_port"] ?? 443);
            $settings["ws_default_path"]        = trim($_POST["ws_default_path"] ?? "/tunnel");
            $settings["ws_default_tls"]         =
                isset($_POST["ws_default_tls"]) && $_POST["ws_default_tls"] === "true"
                ? "true" : "false";
            $settings["ws_default_reconnect"]   = max(1, (int)($_POST["ws_default_reconnect"] ?? 5));
            $settings["ws_default_hs_timeout"]  = max(5, (int)($_POST["ws_default_hs_timeout"] ?? 10));
            // Sanitise path: strip CR/LF, enforce leading slash
            $settings["ws_default_path"] = str_replace(["\r", "\n"], "", $settings["ws_default_path"]);
            if ($settings["ws_default_path"] === "" || $settings["ws_default_path"][0] !== "/") {
                $settings["ws_default_path"] = "/tunnel";
            }

            install_cron_job(
                "/usr/local/bin/php /usr/local/www/wgx/vpn_wg_export.php cron_rotate",
                $settings["auto_cron"] === "true",
                "0",
                "3",
                "*",
                "*",
                "*"
            );

            wgx_save_settings($settings);
            syslog(LOG_NOTICE, "WGX Export Tool: Global Settings saved.");
            wgx_audit_log("Global settings saved");

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => "Global settings saved successfully.",
            ]);
            exit();
        }

        // === 4.F.1 POST: ha_save — save HA sync settings ===========================
        if ($_POST["action"] === "ha_save") {
            if (!csrf_check(false)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF failed"]);
                exit();
            }
            $old = wgx_ha_load();
            $ha = [];
            $ha['enabled']           = ($_POST['ha_enabled']    ?? '') === 'true' ? 'true' : 'false';
            $ha['remote_ip']         = trim($_POST['ha_remote_ip']   ?? '');
            $ha['remote_port']       = (string)(int)($_POST['ha_remote_port'] ?? 443);
            $ha['remote_user']       = trim($_POST['ha_remote_user'] ?? 'admin') ?: 'admin';
            // Never overwrite stored password with an empty one — treat blank as "unchanged".
            if (!empty($_POST['ha_remote_pass'])) {
                $ha['remote_pass'] = base64_encode((string)$_POST['ha_remote_pass']);
            } else {
                $ha['remote_pass'] = (string)($old['remote_pass'] ?? '');
            }
            $ha['verify_tls']        = ($_POST['ha_verify_tls']  ?? '') === 'true' ? 'true' : 'false';
            // Same-network is auto-detected server-side from the remote IP for correctness.
            $ha['same_network']      = wgx_ha_is_same_network($ha['remote_ip']) ? 'true' : 'false';
            $ha['sync_wg_package']   = ($_POST['ha_sync_wg_package']   ?? 'true') === 'true' ? 'true' : 'false';
            $ha['sync_wgx_settings'] = ($_POST['ha_sync_wgx_settings'] ?? 'true') === 'true' ? 'true' : 'false';
            $ha['sync_fw_rules']     = ($_POST['ha_sync_fw_rules']     ?? 'true') === 'true' ? 'true' : 'false';
            $ha['auto_sync']         = ($_POST['ha_auto_sync']         ?? 'true') === 'true' ? 'true' : 'false';
            $ha['last_sync']         = (int)($old['last_sync']   ?? 0);
            $ha['last_status']       = (string)($old['last_status'] ?? '');
            $ha['last_error']        = (string)($old['last_error']  ?? '');

            wgx_ha_save($ha);
            wgx_audit_log("HA Sync settings saved (enabled={$ha['enabled']} target={$ha['remote_ip']})");

            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode([
                "success"      => true,
                "message"      => "HA Sync settings saved.",
                "same_network" => $ha['same_network'] === 'true',
                "source_ip"    => wgx_ha_source_ip($ha['remote_ip']),
            ]);
            exit();
        }

        // === 4.F.2 POST: ha_test — probe the backup ================================
        if ($_POST["action"] === "ha_test") {
            if (!csrf_check(false)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF failed"]);
                exit();
            }
            // Test against the FORM values (unsaved) so the user can verify before saving.
            $ha = wgx_ha_load();
            $ha['remote_ip']   = trim($_POST['ha_remote_ip']   ?? $ha['remote_ip']);
            $ha['remote_port'] = (string)(int)($_POST['ha_remote_port'] ?? $ha['remote_port']);
            $ha['remote_user'] = trim($_POST['ha_remote_user'] ?? $ha['remote_user']) ?: 'admin';
            if (!empty($_POST['ha_remote_pass'])) {
                $ha['remote_pass'] = base64_encode((string)$_POST['ha_remote_pass']);
            }
            $ha['verify_tls']  = ($_POST['ha_verify_tls']  ?? $ha['verify_tls']) === 'true' ? 'true' : 'false';

            $result = wgx_ha_test_connection($ha);
            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode([
                "success"      => $result['ok'],
                "steps"        => $result['steps'],
                "same_network" => wgx_ha_is_same_network($ha['remote_ip']),
                "source_ip"    => wgx_ha_source_ip($ha['remote_ip']),
            ]);
            exit();
        }

        // === 4.F.3 POST: ha_sync_now — manual sync trigger =========================
        if ($_POST["action"] === "ha_sync_now") {
            if (!csrf_check(false)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF failed"]);
                exit();
            }
            $result = wgx_ha_do_sync(true);
            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode([
                "success" => $result['ok'],
                "steps"   => $result['steps'],
            ]);
            exit();
        }

        // === 4.F.5 POST: ha_bootstrap_allow ========================================
        // Run this on the BACKUP box: it installs a WAN pass rule that
        // permits the primary's IP to reach the backup's web-UI port. That's
        // enough to unblock the XMLRPC handshake so the primary can then
        // sync normally. Idempotent — replays for the same primary IP don't
        // duplicate the rule.
        if ($_POST["action"] === "ha_bootstrap_allow") {
            if (!csrf_check(false)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF failed"]);
                exit();
            }
            $primary_raw = trim((string)($_POST['primary_ip'] ?? ''));
            $port        = (int)($_POST['port'] ?? 0);
            $steps       = [];

            // Validate the primary IP/CIDR. Accept single IPv4/IPv6 addresses,
            // or IPv4 subnets (e.g. 203.0.113.0/24) so users can whitelist a
            // /24 rather than one address. Reject hostnames — firewall rules
            // want literal addresses.
            $addr = $primary_raw;
            $bits = null;
            if (strpos($addr, '/') !== false) {
                list($addr, $bits) = explode('/', $addr, 2);
                $bits = (int)$bits;
            }
            $is_v4 = function_exists('is_ipaddrv4') && is_ipaddrv4($addr);
            $is_v6 = function_exists('is_ipaddrv6') && is_ipaddrv6($addr);
            if (!$is_v4 && !$is_v6) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "steps"   => [[
                        "label" => "Validate primary IP", "ok" => false,
                        "msg"   => "Primary IP '{$primary_raw}' is not a valid IPv4/IPv6 address or CIDR. Enter the WAN or LAN address the primary will connect FROM.",
                    ]],
                ]);
                exit();
            }
            if ($bits !== null) {
                if (($is_v4 && ($bits < 8  || $bits > 32)) ||
                    ($is_v6 && ($bits < 32 || $bits > 128))) {
                    ob_end_clean(); header("Content-Type: application/json");
                    echo json_encode([
                        "success" => false,
                        "steps"   => [[
                            "label" => "Validate primary IP", "ok" => false,
                            "msg"   => "CIDR prefix /{$bits} is out of range. Use /8-/32 for IPv4 or /32-/128 for IPv6.",
                        ]],
                    ]);
                    exit();
                }
            }
            $steps[] = ["label" => "Validate primary IP", "ok" => true,
                        "msg"   => "Accepted " . ($bits !== null
                            ? "subnet {$addr}/{$bits}" : "address {$addr}")];

            // Default port to whatever this box's web UI is listening on.
            $local_webui = (int)(config_get_path("system/webgui/port", "") ?: 443);
            if ($port < 1 || $port > 65535) { $port = $local_webui; }
            $steps[] = ["label" => "Rule port", "ok" => true,
                        "msg"   => "TCP {$port}"
                            . ($port === $local_webui ? " (this box's web UI)" : "")];

            // Load rule list, coerce to sequential array.
            $rules = config_get_path("filter/rule", []);
            if (!empty($rules) && !isset($rules[0])) { $rules = [$rules]; }
            $rules = array_values((array)$rules);

            // Find any existing WGX HA-Sync-inbound rule for this same source
            // + port. If found, update it in place instead of appending; if
            // it's already exactly what we'd write, treat as a no-op.
            $target_src   = ($bits !== null) ? "{$addr}/{$bits}" : $addr;
            $target_descr = "WGX: HA Sync inbound from {$target_src}";
            $found_at     = null;
            $identical    = false;
            foreach ($rules as $i => $r) {
                if (!is_array($r)) { continue; }
                if (stripos((string)($r["descr"] ?? ""), "WGX: HA Sync inbound") !== 0) { continue; }
                if (($r["interface"] ?? "") !== "wan") { continue; }
                if ((string)($r["destination"]["port"] ?? "") !== (string)$port) { continue; }
                // Is the source the same?
                $r_src = $bits !== null
                       ? (string)($r["source"]["network"] ?? ($r["source"]["address"] ?? ""))
                       : (string)($r["source"]["address"] ?? "");
                if ($r_src === $target_src) {
                    $found_at  = $i;
                    $identical = ($r["descr"] ?? "") === $target_descr
                              && ($r["type"] ?? "") === "pass";
                    break;
                }
            }

            if ($identical) {
                $steps[] = ["label" => "Firewall rule", "ok" => true,
                            "msg"   => "Rule already present — no changes needed."];
            } else {
                $source = $bits !== null
                        ? ["network" => "{$addr}/{$bits}"]
                        : ["address" => $addr];
                $new_rule = [
                    "type"        => "pass",
                    "interface"   => "wan",
                    "ipprotocol"  => $is_v6 ? "inet6" : "inet",
                    "protocol"    => "tcp",
                    "source"      => $source,
                    "destination" => [
                        "network" => "(self)",
                        "port"    => (string)$port,
                    ],
                    "statetype"   => "keep state",
                    "descr"       => $target_descr,
                ];
                if (function_exists("make_config_revision_entry")) {
                    $new_rule["created"] = make_config_revision_entry();
                }
                if ($found_at !== null) {
                    $rules[$found_at] = $new_rule;
                    $steps[] = ["label" => "Firewall rule", "ok" => true,
                                "msg"   => "Updated existing WGX HA rule at position " . ($found_at + 1) . "."];
                } else {
                    array_unshift($rules, $new_rule);
                    $steps[] = ["label" => "Firewall rule", "ok" => true,
                                "msg"   => "Added new WGX HA rule at top of WAN: pass TCP {$port} from {$target_src} to (self)."];
                }
                config_set_path("filter/rule", $rules);
                write_config("WGX HA Sync: bootstrap allow rule for {$target_src} on TCP {$port}");
                $steps[] = ["label" => "Save config", "ok" => true, "msg" => "config.xml written"];
            }

            if (function_exists("filter_configure")) {
                @filter_configure();
                $steps[] = ["label" => "Firewall reload", "ok" => true,
                            "msg"   => "Ruleset activated — the primary can now reach TCP {$port} on this box."];
            } else {
                $steps[] = ["label" => "Firewall reload", "ok" => false,
                            "msg"   => "filter_configure() not available; the rule will apply on next filter reload."];
            }

            if (function_exists("wgx_audit_log")) {
                wgx_audit_log("HA Sync bootstrap: allow rule for {$target_src} on TCP {$port}");
            }

            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "steps"   => $steps,
                "message" => "Bootstrap allow rule installed. Go back to the PRIMARY box and click Test Connection.",
            ]);
            exit();
        }

        // === 4.F.4 GET-alike POST: ha_status — used by toolbar badge polling =======
        if ($_POST["action"] === "ha_status") {
            $ha = wgx_ha_load();
            // Non-secret fields for populating the modal on open. The
            // password field is deliberately NOT returned; the UI treats
            // blank as "keep existing" on save.
            $local_webui_port = (int)(config_get_path("system/webgui/port", "") ?: 443);
            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode([
                "success"            => true,
                "enabled"            => ($ha['enabled'] ?? 'false') === 'true',
                "configured"         => wgx_ha_is_configured(),
                "last_sync"          => (int)($ha['last_sync']   ?? 0),
                "last_status"        => (string)($ha['last_status'] ?? ''),
                "last_error"         => (string)($ha['last_error']  ?? ''),
                // Persisted, non-secret form values so the modal can
                // repopulate on open.
                "remote_ip"          => (string)($ha['remote_ip']   ?? ''),
                "remote_port"        => (string)($ha['remote_port'] ?? ''),
                "remote_user"        => (string)($ha['remote_user'] ?? 'admin'),
                "has_password"       => !empty($ha['remote_pass']),
                "verify_tls"         => ($ha['verify_tls']  ?? 'true')  === 'true',
                "sync_wg_package"    => ($ha['sync_wg_package']    ?? 'true') === 'true',
                "sync_wgx_settings"  => ($ha['sync_wgx_settings']  ?? 'true') === 'true',
                "sync_fw_rules"      => ($ha['sync_fw_rules']      ?? 'true') === 'true',
                "auto_sync"          => ($ha['auto_sync']          ?? 'true') === 'true',
                // The primary's own web-UI port is a good default for
                // the backup when no port has been saved yet.
                "local_webui_port"   => $local_webui_port,
            ]);
            exit();
        }

        // === 4.G. POST: delete_peer ===
        if ($_POST["action"] === "delete_peer") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode([
                    "success" => false,
                    "message" => "Rate limit exceeded.",
                ]);
                exit();
            }

            $idx = (int) ($_POST["idx"] ?? -1);
            $a_peers = wgx_get_config_array("peer");

            if (!isset($a_peers[$idx])) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Peer not found.",
                ]);
                exit();
            }

            $tun = $a_peers[$idx]["tun"] ?? "";
            $pubkey = $a_peers[$idx]["publickey"] ?? "";
            $del_descr = $a_peers[$idx]["descr"] ?? "(unnamed)";

            if (!empty($tun) && !empty($pubkey)) {
                wgx_wg_exec($wg_bin, ["set", $tun, "peer", $pubkey, "remove"]);
            }

            unset($a_peers[$idx]);
            $a_peers = array_values($a_peers);

            global $config;
            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }

            write_config("WG Suite: Permanently deleted peer '{$del_descr}'");
            wgx_audit_log("Permanently deleted peer '{$del_descr}' (pubkey " . substr($pubkey, 0, 12) . "...)");
            sync_package("wireguard");

            @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";

            if (function_exists("wg_resync")) {
                wg_resync($tun, true);
            } elseif (function_exists("setup_wg")) {
                setup_wg();
            }

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => "Peer deleted successfully.",
            ]);
            wgx_ha_maybe_sync();
            exit();
        }

        // === 4.G2. POST: delete_tunnel ===
        // Deletes a WireGuard tunnel. Mirrors the native package's
        // wg_delete_tunnel semantics: refuses while assigned as a pfSense
        // interface. Peers require an explicit cascade flag and are removed
        // from the kernel and config (rather than left 'Unassigned').
        // Also cleans up the WGX-managed outbound NAT rule for the tunnel.
        if ($_POST["action"] === "delete_tunnel") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode([
                    "success" => false,
                    "message" => "Rate limit exceeded.",
                ]);
                exit();
            }

            $tun_name = trim($_POST["tun_name"] ?? "");
            $confirm  = trim($_POST["confirm_name"] ?? "");
            $cascade  = (($_POST["cascade_peers"] ?? "") === "1");

            if ($tun_name === "" || $confirm !== $tun_name) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Confirmation name did not match the tunnel name. Deletion aborted.",
                ]);
                exit();
            }

            $a_tunnels = wgx_get_config_array("tunnel");
            $tun_idx = -1;
            foreach ($a_tunnels as $ti => $tv) {
                if (is_array($tv) && ($tv["name"] ?? "") === $tun_name) {
                    $tun_idx = $ti;
                    break;
                }
            }
            if ($tun_idx < 0) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Tunnel not found.",
                ]);
                exit();
            }

            // Refuse while assigned as a pfSense interface — same stance as
            // the native package's wg_validate_tunnel_delete(). Unwinding an
            // assignment safely (gateways, routes, rules) is an admin task.
            foreach (config_get_path("interfaces", []) as $ik => $iv) {
                if (is_array($iv) && ($iv["if"] ?? "") === $tun_name) {
                    $if_label = ($iv["descr"] ?? strtoupper($ik)) . " (" . strtoupper($ik) . ")";
                    ob_end_clean();
                    header("Content-Type: application/json");
                    echo json_encode([
                        "success" => false,
                        "message" => "Cannot delete {$tun_name} while it is assigned to {$if_label}. " .
                                     "Unassign it at Interfaces > Assignments first.",
                    ]);
                    exit();
                }
            }

            // Collect this tunnel's peers
            $a_peers = wgx_get_config_array("peer");
            $tun_peer_idxs = [];
            foreach ($a_peers as $pi => $pv) {
                if (is_array($pv) && ($pv["tun"] ?? "") === $tun_name) {
                    $tun_peer_idxs[] = $pi;
                }
            }

            if (!empty($tun_peer_idxs) && !$cascade) {
                $pc = count($tun_peer_idxs);
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success"       => false,
                    "needs_cascade" => true,
                    "peer_count"    => $pc,
                    "message"       => "Tunnel {$tun_name} still has {$pc} peer" . ($pc === 1 ? "" : "s") .
                                       ". Confirm cascade deletion to remove the tunnel and its peers.",
                ]);
                exit();
            }

            @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";

            // Cascade: purge peers from the kernel (best-effort), then config
            $peers_removed = 0;
            if ($cascade && !empty($tun_peer_idxs)) {
                foreach ($tun_peer_idxs as $pi) {
                    $ppk = $a_peers[$pi]["publickey"] ?? "";
                    if ($ppk !== "") {
                        wgx_wg_exec($wg_bin, ["set", $tun_name, "peer", $ppk, "remove"]);
                    }
                    unset($a_peers[$pi]);
                    $peers_removed++;
                }
                $a_peers = array_values($a_peers);
                config_set_path("installedpackages/wireguard/peers/item", $a_peers);
            }

            // Clean up the WGX-managed outbound NAT rule for this tunnel
            $nat_tag = "WGX: Auto-created outbound NAT for {$tun_name}";
            $nat_rules = config_get_path("nat/outbound/rule", []);
            $nat_removed = 0;
            if (is_array($nat_rules) && !empty($nat_rules)) {
                $nat_keep = [];
                foreach ($nat_rules as $nr) {
                    if (is_array($nr) && stripos((string)($nr["descr"] ?? ""), $nat_tag) === 0) {
                        $nat_removed++;
                        continue;
                    }
                    $nat_keep[] = $nr;
                }
                if ($nat_removed > 0) {
                    config_set_path("nat/outbound/rule", array_values($nat_keep));
                }
            }

            // Delete the tunnel — native routine when available (validates,
            // removes config, persists via wg_write_config, resyncs).
            if (function_exists("wg_delete_tunnel")) {
                $del_res = wg_delete_tunnel($tun_name);
                if (!empty($del_res["input_errors"])) {
                    ob_end_clean();
                    header("Content-Type: application/json");
                    echo json_encode([
                        "success" => false,
                        "message" => implode(" ", (array)$del_res["input_errors"]),
                    ]);
                    exit();
                }
            } else {
                // Manual fallback: rebuild the tunnels array and persist
                unset($a_tunnels[$tun_idx]);
                config_set_path(
                    "installedpackages/wireguard/tunnels/item",
                    array_values($a_tunnels)
                );
                write_config("WG Suite: Deleted tunnel '{$tun_name}'");
                if (function_exists("wg_resync")) {
                    wg_resync();
                } elseif (function_exists("setup_wg")) {
                    setup_wg();
                }
            }

            // Best-effort kernel teardown if the interface still lingers
            $if_check = [];
            @exec("/sbin/ifconfig " . escapeshellarg($tun_name) . " 2>/dev/null", $if_check, $if_rc);
            if ((int)$if_rc === 0 && !empty($if_check)) {
                @exec("/sbin/ifconfig " . escapeshellarg($tun_name) . " destroy 2>/dev/null");
            }

            sync_package("wireguard");

            $note = "Deleted tunnel '{$tun_name}'"
                  . ($peers_removed > 0 ? " and {$peers_removed} peer" . ($peers_removed === 1 ? "" : "s") : "")
                  . ($nat_removed > 0 ? ", removed {$nat_removed} WGX outbound NAT rule" . ($nat_removed === 1 ? "" : "s") : "");
            syslog(LOG_NOTICE, "WG Suite: {$note}");
            wgx_audit_log($note);

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => $note . ".",
            ]);
            wgx_ha_maybe_sync();
            exit();
        }

        // === BULK ACTION ===
        if ($_POST["action"] === "bulk_action") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }
            $sub = trim($_POST["sub_action"] ?? "");
            $raw = trim($_POST["indices"] ?? "");
            $idxs = array_filter(
                array_map("intval", explode(",", $raw)),
                fn($i) => $i >= 0
            );
            if (
                empty($idxs) ||
                !in_array(
                    $sub,
                    ["delete", "enable", "disable", "rotate_keys", "extend_expiry"],
                    true
                )
            ) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid request.",
                ]);
                exit();
            }
            $a_peers = wgx_get_config_array("peer");
            $affected_tuns = [];
            foreach ($idxs as $i) {
                if (!isset($a_peers[$i])) {
                    continue;
                }
                $tun = $a_peers[$i]["tun"] ?? "";
                $pubkey = $a_peers[$i]["publickey"] ?? "";
                if ($sub === "delete") {
                    if (!empty($tun) && !empty($pubkey)) {
                        wgx_wg_exec($wg_bin, [
                            "set",
                            $tun,
                            "peer",
                            $pubkey,
                            "remove",
                        ]);
                    }
                    unset($a_peers[$i]);
                    if ($tun) {
                        $affected_tuns[$tun] = true;
                    }
                } elseif ($sub === "enable") {
                    $a_peers[$i]["enabled"] = "yes";
                    if ($tun) {
                        $affected_tuns[$tun] = true;
                    }
                } elseif ($sub === "disable") {
                    $a_peers[$i]["enabled"] = "no";
                    // Kick the peer out of the kernel immediately — a config
                    // flag alone does not terminate the live session.
                    if (!empty($tun) && !empty($pubkey)) {
                        wgx_wg_exec($wg_bin, ["set", $tun, "peer", $pubkey, "remove"]);
                    }
                    if ($tun) {
                        $affected_tuns[$tun] = true;
                    }
                } elseif ($sub === "rotate_keys") {
                    $pair = wgx_gen_keypair($wg_bin);
                    if (!empty($pair["pub"])) {
                        // Purge the retired key before installing the new one.
                        if (!empty($tun) && !empty($pubkey)) {
                            wgx_wg_exec($wg_bin, ["set", $tun, "peer", $pubkey, "remove"]);
                        }
                        $a_peers[$i]["publickey"] = $pair["pub"];
                        $a_peers[$i]["privatekey"] = $pair["priv"];
                        $a_peers[$i]["key_created"] = time();
                        if ($tun) {
                            $affected_tuns[$tun] = true;
                        }
                    }
                } elseif ($sub === "extend_expiry") {
                    $extend_days = max(1, min(3650, (int)($_POST["extend_days"] ?? 30)));
                    $current_expiry = (int)($a_peers[$i]["expire_time"] ?? 0);
                    // Extend from now if already expired, otherwise extend from current expiry
                    $base = ($current_expiry > time()) ? $current_expiry : time();
                    $a_peers[$i]["expire_time"] = $base + ($extend_days * 86400);
                    // Clear the expiry warning flag so it can fire again if needed
                    unset($a_peers[$i]["wgx_expiry_warned"]);
                }
            }
            $a_peers = array_values($a_peers);
            global $config;
            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }
            write_config(
                "WG Suite: Bulk action '{$sub}' on " . count($idxs) . " peer(s)"
            );
            wgx_audit_log("Bulk action '{$sub}' applied to " . count($idxs) . " peer(s)");
            sync_package("wireguard");
            wgx_kernel_sync(array_keys($affected_tuns));
            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode(["success" => true]);
            wgx_ha_maybe_sync();
            exit();
        }

        // === 4.H. POST: kill_peer ===
        if ($_POST["action"] === "kill_peer") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            $pubkey = trim($_POST["pubkey"] ?? "");
            $tun = trim($_POST["tun"] ?? "");

            if (!in_array($tun, wgx_valid_tunnel_names(), true) ||
                !preg_match('/^[A-Za-z0-9+\/]{43}=$/', $pubkey)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid tunnel or public key.",
                ]);
                exit();
            }

            wgx_wg_exec($wg_bin, ["set", $tun, "peer", $pubkey, "remove"]);

            global $config;
            $a_peers = wgx_get_config_array("peer");

            foreach ($a_peers as &$p) {
                if (
                    ($p["publickey"] ?? "") === $pubkey &&
                    ($p["tun"] ?? "") === $tun
                ) {
                    $p["enabled"] = "no";
                }
            }

            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }

            write_config("WG Suite: Killed peer connection {$pubkey}");
            wgx_audit_log("Killed active connection for peer pubkey " . substr($pubkey, 0, 12) . "...");
            // Regenerate the on-disk conf so a tunnel/service restart cannot
            // silently re-admit the peer we just kicked.
            wgx_kernel_sync([$tun]);

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => "Peer connection dropped and disabled.",
            ]);
            exit();
        }

        // === 4.I. POST: rotate_keys ===
        if ($_POST["action"] === "ping_peer") {
            if (!csrf_check(false)) { ob_end_clean(); header("Content-Type: application/json"); echo json_encode(["success"=>false,"message"=>"CSRF failed"]); exit(); }
            $ping_ip = trim($_POST["peer_ip"] ?? "");
            if (empty($ping_ip) || !is_ipaddr($ping_ip)) {
                ob_end_clean(); header("Content-Type: application/json");
                echo json_encode(["success"=>false,"message"=>"Invalid IP address."]);
                exit();
            }
            // Sanitise - only allow plain IPs, strip CIDR if present
            $ping_ip = explode('/', $ping_ip)[0];
            $output = [];
            $ping_cmd = is_ipaddrv6($ping_ip) ? 'ping6' : 'ping';
            // FreeBSD ping's -W is in MILLISECONDS (Linux uses seconds);
            // '-W 2' waited only 2 ms per reply so peers always looked down.
            exec(escapeshellcmd($ping_cmd) . ' -c 3 -W 2000 ' . escapeshellarg($ping_ip) . ' 2>&1', $output);
            $result = implode("\n", $output);
            $success = (stripos($result, ' 0% packet loss') !== false || stripos($result, '0.0% packet loss') !== false);
            ob_end_clean(); header("Content-Type: application/json");
            echo json_encode(["success"=>true,"reachable"=>$success,"output"=>htmlspecialchars($result)]);
            exit();
        }

        if ($_POST["action"] === "rotate_keys") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            $idx = (int) ($_POST["idx"] ?? -1);
            $a_peers = wgx_get_config_array("peer");

            if (!isset($a_peers[$idx])) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Peer not found.",
                ]);
                exit();
            }

            $pair = wgx_gen_keypair($wg_bin);
            if (empty($pair["pub"])) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Failed to generate keys.",
                ]);
                exit();
            }

            $tun_name = $a_peers[$idx]["tun"];
            $old_pub  = $a_peers[$idx]["publickey"] ?? "";
            $a_peers[$idx]["publickey"] = $pair["pub"];
            $a_peers[$idx]["privatekey"] = $pair["priv"];
            $a_peers[$idx]["key_created"] = time();

            global $config;
            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }

            wgx_record_config_snapshot($pair["pub"], 'Keys rotated', [
                'tunnel'      => $tun_name,
                'new_pubkey'  => substr($pair["pub"], 0, 12) . '…',
            ]);
            write_config(
                "WG Suite: Rotated keys for peer {$a_peers[$idx]["descr"]}"
            );
            sync_package("wireguard");

            // Purge the retired public key from the kernel, then fully sync
            // so the NEW key is actually loaded (wg_resync alone only
            // rewrites the .conf files on disk).
            if (!empty($old_pub) && !empty($tun_name)) {
                wgx_wg_exec($wg_bin, ["set", $tun_name, "peer", $old_pub, "remove"]);
            }
            wgx_kernel_sync([$tun_name]);

            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            echo json_encode([
                "success" => true,
                "message" => "Keys rotated successfully.",
                "new_priv" => $pair["priv"],
                "new_pub" => $pair["pub"],
            ]);
            wgx_ha_maybe_sync();
            exit();
        }

        // === 4.J. POST: bulk_csv ===
        if ($_POST["action"] === "bulk_csv") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }

            $csvData = trim($_POST["csv_data"] ?? "");
            $tunName = trim($_POST["tun"] ?? "");

            if (empty($csvData) || empty($tunName)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Missing data.",
                ]);
                exit();
            }

            // Clean Windows \r\n line endings which can corrupt IP parsing
            $csvData = str_replace(["\r\n", "\r"], "\n", $csvData);
            $lines = explode("\n", $csvData);
            $processed = 0;
            $a_peers = wgx_get_config_array("peer");

            foreach ($lines as $line) {
                $cols = str_getcsv(trim($line));
                if (count($cols) >= 2) {
                    $descr = trim($cols[0]);
                    $ip = trim($cols[1]);

                    $ip_parts = explode("/", $ip);
                    if (is_ipaddr($ip_parts[0])) {
                        $pair = wgx_gen_keypair($wg_bin);
                        $psk = wgx_gen_psk_key($wg_bin);

                        if (!empty($pair["pub"])) {
                            $new_peer = [
                                "enabled" => "yes",
                                "tun" => $tunName,
                                "descr" => $descr,
                                "dynamic" => "yes",
                                "endpoint" => "",
                                "port" => "",
                                "keepalive" => "25",
                                "publickey" => $pair["pub"],
                                "privatekey" => $pair["priv"],
                                "key_created" => time(),
                                "presharedkey" => $psk,
                                "allowedips" => [
                                    "row" => [
                                        [
                                            "address" => $ip_parts[0],
                                            "mask" => "32",
                                            "descr" => "",
                                        ],
                                    ],
                                ],
                            ];
                            $a_peers[] = $new_peer;
                            $processed++;

                            // === INSTANT KERNEL INJECTION (MIRRORING ADD_PEER) ===
                            $wg_args = ["set", $tunName, "peer", $pair["pub"]];
                            if (!empty($psk)) {
                                $tmp_psk = tempnam(
                                    sys_get_temp_dir(),
                                    "wg_psk_"
                                );
                                file_put_contents($tmp_psk, $psk);
                                chmod($tmp_psk, 0600);
                                $wg_args[] = "preshared-key";
                                $wg_args[] = $tmp_psk;
                            }
                            $wg_args[] = "persistent-keepalive";
                            $wg_args[] = "25";
                            $wg_args[] = "allowed-ips";
                            $wg_args[] = $ip_parts[0] . "/32";

                            wgx_wg_exec($wg_bin, $wg_args);
                            if (isset($tmp_psk)) {
                                @unlink($tmp_psk);
                            }
                        }
                    }
                }
            }

            if ($processed > 0) {
                global $config;
                if (function_exists("config_set_path")) {
                    config_set_path(
                        "installedpackages/wireguard/peers/item",
                        $a_peers
                    );
                } else {
                    if (
                        !isset(
                            $config["installedpackages"]["wireguard"]["peers"]["item"]
                        )
                    ) {
                        $config["installedpackages"]["wireguard"]["peers"]["item"] = [];
                    }
                    $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
                }

                write_config(
                    "WG Export Tool: Provisioned {$processed} peers on tunnel '{$tunName}'"
                );
                $operator = $_SESSION["Username"] ?? "unknown";
                syslog(
                    LOG_NOTICE,
                    "WireGuard Export Tool: {$processed} peers provisioned on '{$tunName}' by {$operator}"
                );

                sync_package("wireguard");
                @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
                @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
                @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";

                if (function_exists("wg_resync")) {
                    wg_resync($tun_name, true);
                } elseif (function_exists("setup_wg")) {
                    setup_wg();
                }
                if (function_exists("clear_subsystem_dirty")) {
                    clear_subsystem_dirty("wireguard");
                }
                @unlink("/tmp/wireguard.dirty");
            }

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => "Provisioned {$processed} peers successfully.",
            ]);
            exit();
        }

        // === 4.K.5 POST: email_ws_bundle — email the WS peer bundle as attachment ===

        // === 4.L. POST: email_peer ===
        if ($_POST["action"] === "email_peer") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }
            global $config;
            if (empty(config_get_path("notifications/smtp/ipaddress"))) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" =>
                    "SMTP not configured in pfSense System Settings.",
                ]);
                exit();
            }
            $to = trim($_POST["email"] ?? "");
            $conf_text = trim($_POST["conf"] ?? "");
            $peer_name = str_replace(["\r", "\n"], " ", trim($_POST["name"] ?? ""));
            if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid email address.",
                ]);
                exit();
            }
            $subject = "WireGuard VPN Configuration: {$peer_name}";
            $message = "Hello,\n\nHere is your WireGuard VPN configuration profile for: {$peer_name}\n\n";
            $message .= "=================================\n";
            $message .= $conf_text . "\n";
            $message .= "=================================\n\n";

            $b64_conf = base64_encode($conf_text);
            $message .= "-- MOBILE ONE-CLICK IMPORT --\n";
            $message .=
                "If you are opening this email on iOS or Android, tap the link below to instantly import this profile into the WireGuard app:\n";
            $message .= "wireguard://import/{$b64_conf}\n\n";
            $message .=
                "Otherwise, save the raw text above as a .conf file and import it manually.\n";

            if (!function_exists("send_smtp_message")) {
                @include_once "/etc/inc/notify.inc";
            }
            if (!function_exists("send_smtp_message")) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "send_smtp_message() not available.",
                ]);
                exit();
            }
            $conf_filename =
                preg_replace("/[^a-z0-9_-]/i", "_", $peer_name) . ".conf";
            $full_body =
                "Hello,

Here is your WireGuard VPN configuration for: {$peer_name}

" .
                "============ {$conf_filename} ============
" .
                $conf_text .
                "
" .
                "===========================================

" .
                "MOBILE IMPORT
" .
                "Tap the link below on your phone to import directly into the WireGuard app:

" .
                "wireguard://import/" .
                base64_encode($conf_text) .
                "
";
            $original_notify = config_get_path(
                "notifications/smtp/notifyemailaddress",
                ""
            );
            config_set_path("notifications/smtp/notifyemailaddress", $to);
            $sent = send_smtp_message($full_body, $subject);
            config_set_path(
                "notifications/smtp/notifyemailaddress",
                $original_notify
            );
            $ok = $sent !== false;
            ob_end_clean();
            header("Content-Type: application/json");
            if ($ok) {
                syslog(
                    LOG_NOTICE,
                    "WG Suite: Emailed config for '{$peer_name}' to {$to}"
                );
                echo json_encode([
                    "success" => true,
                    "message" => "Configuration emailed to {$to}.",
                ]);
            } else {
                $smtp_ip = config_get_path("notifications/smtp/ipaddress", "");
                $hint = empty($smtp_ip)
                    ? "SMTP not configured. Go to System > Advanced > Notifications."
                    : "Send failed via {$smtp_ip}. Verify settings in System > Advanced > Notifications.";
                echo json_encode(["success" => false, "message" => $hint]);
            }
            exit();
        }

        // === 4.M. POST: add_peer ===
        if ($_POST["action"] === "add_peer") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" =>
                    "CSRF validation failed. Refresh the page and try again.",
                ]);
                exit();
            }

            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode([
                    "success" => false,
                    "message" => "Rate limit exceeded.",
                ]);
                exit();
            }

            $valid_tunnels = wgx_valid_tunnel_names();
            $tun_name = trim($_POST["tun"] ?? "");

            // Per-tunnel peer limit check
            $all_tuns = wgx_get_config_array("tunnel");
            foreach ($all_tuns as $_t) {
                if (($_t["name"] ?? "") === $tun_name) {
                    $tun_limit = (int)($_t["wgx_peer_limit"] ?? 0);
                    if ($tun_limit > 0) {
                        $current_count = 0;
                        foreach (wgx_get_config_array("peer") as $_p) {
                            if (($_p["tun"] ?? "") === $tun_name && ($_p["enabled"] ?? "no") === "yes") {
                                $current_count++;
                            }
                        }
                        if ($current_count >= $tun_limit) {
                            ob_end_clean();
                            header("Content-Type: application/json");
                            echo json_encode([
                                "success" => false,
                                "message" => "Peer limit reached for tunnel {$tun_name} (limit: {$tun_limit}). Disable or delete an existing peer first.",
                            ]);
                            exit();
                        }
                    }
                    break;
                }
            }
            $publickey = trim($_POST["publickey"] ?? "");
            $privatekey = trim($_POST["privatekey"] ?? "");
            $assigned_raw = trim($_POST["assignedip"] ?? "");
            $descr = trim($_POST["descr"] ?? "New Peer");
            $psk = trim($_POST["presharedkey"] ?? "");
            $keepalive = trim($_POST["keepalive"] ?? "25");
            $schedule = trim($_POST["schedule"] ?? "always");
            $sched_date_from = trim($_POST["sched_date_from"] ?? "");
            $sched_date_to   = trim($_POST["sched_date_to"]   ?? "");
            if (
                !in_array(
                    $schedule,
                    [
                        "always",
                        "weekdays",
                        "weekends",
                        "business_hours",
                        "nights",
                    ],
                    true
                )
            ) {
                $schedule = "always";
            }
            $expiry_days = (int) ($_POST["expiry"] ?? 0);
            $peer_quota_exempt =
                ($_POST["quota_exempt"] ?? "1") === "1" ? "1" : "0";
            $peer_quota_limit = (int) ($_POST["quota_limit_gb"] ?? 0);
            $peer_tier = trim($_POST["tier"] ?? "admin");
            $peer_target = trim($_POST["target"] ?? "");
            if (!empty($peer_target) && !is_subnet($peer_target)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid target subnet format.",
                ]);
                exit();
            }
            $peer_autorotate = (int) ($_POST["autorotate"] ?? 0);

            if (!in_array($tun_name, $valid_tunnels, true)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid tunnel name.",
                ]);
                exit();
            }
            if (!preg_match('/^[A-Za-z0-9+\/]{43}=$/', $publickey)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid WireGuard public key format.",
                ]);
                exit();
            }
            if ($keepalive !== "" && !ctype_digit($keepalive)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Keep Alive must be a valid number.",
                ]);
                exit();
            }

            $settings = wgx_load_settings();
            if ($settings["enforce_psk"] === "true" && empty($psk)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" =>
                    "Global Policy Violation: Pre-Shared Key is strictly required.",
                ]);
                exit();
            }

            $assigned_ips = array_filter(
                array_map("trim", explode(",", $assigned_raw))
            );
            $allowedips_array = [];
            foreach ($assigned_ips as $assigned) {
                if (strpos($assigned, "/") !== false) {
                    $parts = explode("/", $assigned, 2);
                    $addr = trim($parts[0]);
                    $mask = (string) (int) trim($parts[1]);
                } else {
                    $addr = $assigned;
                    $mask = "32";
                }
                if (!is_ipaddr($addr) || (int) $mask < 0 || (int) $mask > 128) {
                    ob_end_clean();
                    header("Content-Type: application/json");
                    echo json_encode([
                        "success" => false,
                        "message" => "Invalid IP address or mask: {$assigned}",
                    ]);
                    exit();
                }
                $allowedips_array[] = [
                    "address" => $addr,
                    "mask" => $mask,
                    "descr" => "",
                ];
            }
            if (empty($allowedips_array)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "At least one Assigned IP is required.",
                ]);
                exit();
            }

            $descr = preg_replace('/[\x00-\x1F\x7F]/', "", $descr);
            $descr = substr($descr, 0, 128);

            $existing_peers = wgx_get_config_array("peer");
            foreach ($existing_peers as $ep) {
                if (
                    is_array($ep) &&
                    ($ep["tun"] ?? "") === $tun_name &&
                    ($ep["publickey"] ?? "") === $publickey
                ) {
                    ob_end_clean();
                    header("Content-Type: application/json");
                    echo json_encode([
                        "success" => false,
                        "message" =>
                        "A peer with this public key already exists on that tunnel.",
                    ]);
                    exit();
                }
            }

            $ip_conflicts = wgx_check_ip_conflicts(
                $tun_name,
                $allowedips_array
            );
            if (!empty($ip_conflicts)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" =>
                    "IP Conflict Detected: " . implode("; ", $ip_conflicts),
                ]);
                exit();
            }

            // === Per-peer WebSocket override (optional) ===
            $peer_ws_override = [];
            $peer_ws_remote_ip   = str_replace(["\r", "\n"], '', trim($_POST["peer_ws_remote_ip"]   ?? ""));
            $peer_ws_remote_port = (int)($_POST["peer_ws_remote_port"] ?? 443);
            $peer_ws_path        = str_replace(["\r", "\n"], '', trim($_POST["peer_ws_path"]        ?? ""));
            if (!empty($peer_ws_remote_ip)) {
                if ($peer_ws_path === "" || $peer_ws_path[0] !== "/") {
                    $peer_ws_path = "/tunnel";
                }
                $peer_ws_override = [
                    "remote_ip"   => $peer_ws_remote_ip,
                    "remote_port" => (string)$peer_ws_remote_port,
                    "ws_path"     => $peer_ws_path,
                ];
            }

            $new_peer = [
                "enabled" => "yes",
                "tun" => $tun_name,
                "descr" => $descr,
                "dynamic" => "yes",
                "endpoint" => "",
                "port" => "",
                "keepalive" => $keepalive,
                // The pfSense WireGuard package reads 'persistentkeepalive'
                // when regenerating the tunnel .conf. Without it the server
                // peer block omits PersistentKeepalive. Write both so the
                // package and this tool's own UI stay in sync.
                "persistentkeepalive" => $keepalive,
                "publickey" => $publickey,
                "wgx_schedule" => $schedule,
                "wgx_sched_from" => ($schedule === 'date_range' && !empty($sched_date_from)) ? $sched_date_from : "",
                "wgx_sched_to"   => ($schedule === 'date_range' && !empty($sched_date_to))   ? $sched_date_to   : "",
                "wgx_tier" => $peer_tier,
                "wgx_target" => $peer_target,
                "wgx_autorotate" => $peer_autorotate,
                "allowedips" => [
                    "row" => $allowedips_array,
                ],
            ];

            if (!empty($privatekey)) {
                $new_peer["privatekey"] = $privatekey;
            }
            if (!empty($psk)) {
                $new_peer["presharedkey"] = $psk;
            }
            if ($expiry_days > 0) {
                $new_peer["expire_time"] = time() + $expiry_days * 86400;
            }
            $new_peer["key_created"] = time();
            // QR/conf download token — valid for 24 hours after provisioning
            $new_peer["wgx_conf_token"]   = bin2hex(random_bytes(16));
            $new_peer["wgx_conf_token_ts"] = time();
            $new_peer["wgx_quota_exempt"] = $peer_quota_exempt;
            $new_peer["wgx_quota_limit_gb"] =
                $peer_quota_limit > 0 ? (string) $peer_quota_limit : "0";

            if (!empty($peer_ws_override)) {
                $new_peer["wgx_ws_override"] = $peer_ws_override;
            }

            // Mark the peer as WebSocket transport if the target tunnel is a
            // WS tunnel, or the admin explicitly chose WebSocket transport.
            // This flag is what makes the export modal return TCP 443 as the
            // endpoint instead of the WireGuard UDP port.
            $peer_transport = trim($_POST["transport"] ?? "standard");
            if ($peer_transport === "websocket" || wgx_tunnel_is_ws($tun_name)) {
                $new_peer["wgx_ws_transport"] = "1";
            }

            // Store peer email if provided — used to pre-fill email modal
            $peer_email = trim($_POST["peer_email"] ?? "");
            if (!empty($peer_email) && filter_var($peer_email, FILTER_VALIDATE_EMAIL)) {
                $new_peer["wgx_email"] = $peer_email;
            }

            // Offline alert threshold
            $offline_alert_hours = max(0, min(720, (int)($_POST["offline_alert_hours"] ?? 0)));
            $new_peer["wgx_offline_alert_hours"] = (string)$offline_alert_hours;

            // Peer group
            $peer_group = substr(trim($_POST["peer_group"] ?? ""), 0, 64);
            $peer_group = preg_replace('/[^a-zA-Z0-9 _\-]/', '', $peer_group);
            if ($peer_group !== "") {
                $new_peer["wgx_group"] = $peer_group;
            }

            // Store admin notes — never exported to peer config
            $peer_notes = substr(trim($_POST["peer_notes"] ?? ""), 0, 500);
            if ($peer_notes !== "") {
                $new_peer["wgx_notes"] = $peer_notes;
            }

            // Per-peer DNS override — replaces tunnel-level DNS in exported .conf
            $peer_dns = trim($_POST["peer_dns_override"] ?? "");
            if (!empty($peer_dns)) {
                // Validate each entry is a valid IP
                $dns_parts = array_filter(array_map('trim', explode(',', $peer_dns)));
                $valid_dns = array_filter($dns_parts, fn($d) => is_ipaddr($d) || is_ipaddrv6($d));
                if (!empty($valid_dns)) {
                    $new_peer["wgx_dns_override"] = implode(', ', $valid_dns);
                }
            }

            $a_peers = wgx_get_config_array("peer");
            $a_peers[] = $new_peer;
            wgx_send_webhook('peer_add', "New peer '{$descr}' provisioned on tunnel '{$tun_name}'.", ['peer' => $descr, 'tun' => $tun_name]);

            global $config;
            if (function_exists("config_set_path")) {
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
            } else {
                if (
                    !isset(
                        $config["installedpackages"]["wireguard"]["peers"]["item"]
                    ) ||
                    !is_array(
                        $config["installedpackages"]["wireguard"]["peers"]["item"]
                    )
                ) {
                    if (!isset($config["installedpackages"])) {
                        $config["installedpackages"] = [];
                    }
                    if (!isset($config["installedpackages"]["wireguard"])) {
                        $config["installedpackages"]["wireguard"] = [];
                    }
                    if (
                        !isset(
                            $config["installedpackages"]["wireguard"]["peers"]
                        )
                    ) {
                        $config["installedpackages"]["wireguard"]["peers"] = [];
                    }
                    $config["installedpackages"]["wireguard"]["peers"]["item"] = [];
                }
                $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
            }

            write_config(
                "WG Export Tool: Provisioned peer '{$descr}' on tunnel '{$tun_name}'"
            );
            wgx_record_config_snapshot($publickey, 'Provisioned', [
                'tunnel'     => $tun_name,
                'assigned_ip'=> implode(', ', array_column($allowedips_array, 'address')),
                                       'tier'       => $peer_tier,
                                       'schedule'   => $schedule,
                                       'keepalive'  => $keepalive,
                                       'expiry'     => $expiry_days > 0 ? date('Y-m-d', time() + $expiry_days * 86400) : 'None',
            ]);
            $operator = $_SESSION["Username"] ?? "unknown";
            syslog(
                LOG_NOTICE,
                "WireGuard Export Tool: Peer '{$descr}' provisioned on '{$tun_name}' by {$operator}"
            );

            // === INSTANT KERNEL INJECTION ===
            if (!empty($wg_bin)) {
                $wg_args = ["set", $tun_name, "peer", $publickey];
                if (!empty($psk)) {
                    $tmp_psk = tempnam(sys_get_temp_dir(), "wg_psk_");
                    file_put_contents($tmp_psk, $psk);
                    chmod($tmp_psk, 0600);
                    $wg_args[] = "preshared-key";
                    $wg_args[] = $tmp_psk;
                }
                $wg_args[] = "persistent-keepalive";
                $wg_args[] = !empty($keepalive) ? $keepalive : "25";
                $ip_list_parts = [];
                foreach ($allowedips_array as $ip_entry) {
                    $ip_list_parts[] =
                        $ip_entry["address"] . "/" . $ip_entry["mask"];
                }
                $wg_args[] = "allowed-ips";
                $wg_args[] = implode(",", $ip_list_parts);
                wgx_wg_exec($wg_bin, $wg_args);
                if (isset($tmp_psk)) {
                    @unlink($tmp_psk);
                    unset($tmp_psk);
                }
            }
            // ================================

            // Load the official package's apply helpers FIRST, then apply.
            @include_once "/usr/local/pkg/wireguard/includes/wg_globals.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg.inc";
            @include_once "/usr/local/pkg/wireguard/includes/wg_service.inc";

            // CRITICAL: wg_resync() only regenerates the .conf files on disk; it
            // does NOT load anything into the running kernel. The function that
            // actually creates/brings up the interface and loads peers from
            // config is wg_tunnel_sync() — and it only does so while the
            // WireGuard service is running. So make sure the service is up, then
            // do a real tunnel sync. This is what was missing: the peer was only
            // ever live via the fragile `wg set` above and never authoritatively
            // applied, so it never got (or kept) a handshake.
            if (function_exists("wg_toggle_wireguard")) {
                // Starts the service if WireGuard is enabled but not running.
                wg_toggle_wireguard();
            }

            $applied = false;
            if (function_exists("wg_tunnel_sync")) {
                // Regenerates confs (calls wg_resync internally), creates/updates
                // the interface, loads peers into the kernel, purges rogue peers,
                // and reconfigures routing + pf.
                wg_tunnel_sync([$tun_name], true);
                $applied = true;
            } elseif (function_exists("wg_resync")) {
                // Fallback for older package layouts.
                wg_resync();
                sync_package("wireguard");
                $applied = true;
            } else {
                sync_package("wireguard");
            }

            if (function_exists("clear_subsystem_dirty")) {
                clear_subsystem_dirty("wireguard");
            }
            @unlink("/tmp/wireguard.dirty");

            $a_tunnels_for_nat = wgx_get_config_array("tunnel");
            $tun_subnet = null;
            foreach ($a_tunnels_for_nat as $t) {
                if (($t["name"] ?? "") === $tun_name) {
                    $tun_addrs =
                        isset($t["addresses"]) && is_array($t["addresses"])
                        ? $t["addresses"]
                        : [];
                    $raw_row = $tun_addrs["item"] ?? ($tun_addrs["row"] ?? []);
                    if (is_array($raw_row) && !empty($raw_row)) {
                        if (isset($raw_row["address"])) {
                            $addr = $raw_row["address"];
                            $mask = (int) ($raw_row["mask"] ?? 24);
                        } elseif (
                            isset($raw_row[0]) &&
                            is_array($raw_row[0]) &&
                            isset($raw_row[0]["address"])
                        ) {
                            $addr = $raw_row[0]["address"];
                            $mask = (int) ($raw_row[0]["mask"] ?? 24);
                        }
                        if (isset($addr) && is_ipaddr($addr)) {
                            $tun_subnet =
                                gen_subnet($addr, $mask) . "/" . $mask;
                        }
                    }
                    break;
                }
            }

            if ($tun_subnet) {
                $nat_exists = false;
                if (!isset($config["nat"]["outbound"])) {
                    $config["nat"]["outbound"] = [];
                }
                if (
                    !isset($config["nat"]["outbound"]["rule"]) ||
                    !is_array($config["nat"]["outbound"]["rule"])
                ) {
                    $config["nat"]["outbound"]["rule"] = [];
                } elseif (
                    !empty($config["nat"]["outbound"]["rule"]) &&
                    !isset($config["nat"]["outbound"]["rule"][0])
                ) {
                    $config["nat"]["outbound"]["rule"] = [
                        $config["nat"]["outbound"]["rule"],
                    ];
                }

                foreach ($config["nat"]["outbound"]["rule"] as $r) {
                    if (($r["source"]["network"] ?? "") === $tun_subnet) {
                        $nat_exists = true;
                        break;
                    }
                }
                if (!$nat_exists) {
                    if (
                        empty($config["nat"]["outbound"]["mode"]) ||
                        $config["nat"]["outbound"]["mode"] === "automatic"
                    ) {
                        $config["nat"]["outbound"]["mode"] = "hybrid";
                    }
                    $config["nat"]["outbound"]["rule"][] = [
                        "source" => ["network" => $tun_subnet],
                        "sourceport" => "",
                        "descr" => "WGX Auto-NAT for {$tun_name}",
                        "target" => "",
                        "interface" => "wan",
                        "destination" => ["any" => true],
                        "natport" => "",
                        "created" => make_config_revision_entry(),
                    ];
                    write_config(
                        "WGX: Auto-created outbound NAT for {$tun_name}"
                    );
                    filter_configure();
                }
            }

            // === ENTERPRISE ZERO-TRUST FIREWALL ENGINE ===
            if ($peer_tier !== "admin") {
                if (
                    !isset($config["filter"]["rule"]) ||
                    !is_array($config["filter"]["rule"])
                ) {
                    $config["filter"]["rule"] = [];
                } elseif (
                    !empty($config["filter"]["rule"]) &&
                    !isset($config["filter"]["rule"][0])
                ) {
                    $config["filter"]["rule"] = [$config["filter"]["rule"]];
                }

                $tun_iface = "";
                if (
                    isset($config["interfaces"]) &&
                    is_array($config["interfaces"])
                ) {
                    foreach ($config["interfaces"] as $opt => $if_data) {
                        if (($if_data["if"] ?? "") === $tun_name) {
                            $tun_iface = $opt;
                            break;
                        }
                    }
                }

                if (!empty($tun_iface)) {
                    $new_zt_rules = [];
                    foreach ($allowedips_array as $assigned) {
                        $peer_ip = $assigned["address"];

                        if ($peer_tier === "internet_only") {
                            // Rule: Block RFC1918 Private Address Space
                            $rfc1918 = [
                                "192.168.0.0/16",
                                "172.16.0.0/12",
                                "10.0.0.0/8",
                            ];
                            foreach ($rfc1918 as $net) {
                                $new_zt_rules[] = [
                                    "type" => "block",
                                    "interface" => $tun_iface,
                                    "ipprotocol" => "inet",
                                    "protocol" => "any",
                                    "source" => ["address" => $peer_ip],
                                    "destination" => ["network" => $net],
                                    "descr" => "Zero-Trust [BYOD]: Block {$descr} from internal LAN ({$net})",
                                    "created" => make_config_revision_entry(),
                                ];
                            }
                        } elseif (
                            $peer_tier === "vendor" &&
                            !empty($peer_target)
                        ) {
                            // Rule 1: Explicit Pass to Target (Evaluates before block)
                            $new_zt_rules[] = [
                                "type" => "pass",
                                "interface" => $tun_iface,
                                "ipprotocol" => "inet",
                                "protocol" => "any",
                                "source" => ["address" => $peer_ip],
                                "destination" => ["network" => $peer_target],
                                "descr" => "Zero-Trust [Vendor]: Allow {$descr} to target {$peer_target}",
                                "created" => make_config_revision_entry(),
                            ];

                            // Rule 2: Default Deny (Block All)
                            $new_zt_rules[] = [
                                "type" => "block",
                                "interface" => $tun_iface,
                                "ipprotocol" => "inet",
                                "protocol" => "any",
                                "source" => ["address" => $peer_ip],
                                "destination" => ["any" => true],
                                "descr" => "Zero-Trust [Vendor]: Default Deny for {$descr}",
                                "created" => make_config_revision_entry(),
                            ];
                        }
                    }
                    if (!empty($new_zt_rules)) {
                        // Prepend the new Zero-Trust rules to the top of the list so they evaluate first
                        $config["filter"]["rule"] = array_merge(
                            $new_zt_rules,
                            $config["filter"]["rule"]
                        );
                        write_config(
                            "WGX: Auto-deployed Zero-Trust firewall policies for {$descr}"
                        );
                        filter_configure();
                    }
                }
            }
            // ===============================================

            // === QUOTA ENFORCEMENT: AUTO-CREATE ALIAS + FLOATING BLOCK RULE ===
            // When any peer is provisioned with a quota (non-exempt), ensure:
            //   1. WGX_THROTTLED alias exists (populated by wgx_expire.php cron)
            //   2. A floating block rule targeting that alias exists
            // This means the admin never needs to touch Firewall rules manually.
            if ($peer_quota_exempt !== "1") {
                // ── 1. Create WGX_THROTTLED alias if missing ─────────────────
                $all_aliases = config_get_path("aliases/alias", []);
                if (!empty($all_aliases) && !isset($all_aliases[0])) {
                    $all_aliases = [$all_aliases];
                }
                $alias_exists = false;
                foreach ($all_aliases as $a) {
                    if (($a["name"] ?? "") === "WGX_THROTTLED") {
                        $alias_exists = true;
                        break;
                    }
                }
                if (!$alias_exists) {
                    $global_quota_gb = max(
                        1,
                        (int) ($settings["quota_limit_gb"] ?? 100)
                    );
                    $all_aliases[] = [
                        "name" => "WGX_THROTTLED",
                        "type" => "host",
                        "address" => "",
                        "descr" =>
                        "WG Suite: Peers exceeding their data quota. Managed automatically — do not edit manually.",
                        "detail" => "",
                    ];
                    config_set_path("aliases/alias", $all_aliases);
                    write_config("WG Suite: Created WGX_THROTTLED alias");
                    syslog(
                        LOG_NOTICE,
                        "WG Suite: Created WGX_THROTTLED alias."
                    );
                }

                // ── 2. Create floating block rule if missing ─────────────────
                // A floating rule applies to ALL interfaces and both directions,
                // so it works regardless of which WireGuard tunnel the peer is on.
                // We create it once — wgx_expire.php keeps the alias current.
                $float_rules = config_get_path("filter/rule", []);
                if (!empty($float_rules) && !isset($float_rules[0])) {
                    $float_rules = [$float_rules];
                }
                $rule_exists = false;
                foreach ($float_rules as $fr) {
                    if (
                        ($fr["descr"] ?? "") ===
                        "WG Suite: Block over-quota peers [WGX_THROTTLED]"
                    ) {
                        $rule_exists = true;
                        break;
                    }
                }
                if (!$rule_exists) {
                    // Build the floating block rule
                    $wgx_block_rule = [
                        "type" => "block",
                        "floating" => "yes",
                        "direction" => "any",
                        "quick" => "yes", // match first, stop processing
                        "interface" => "", // empty = all interfaces (floating)
                        "ipprotocol" => "inet46", // IPv4 + IPv6
                        "protocol" => "any",
                        "source" => ["address" => "WGX_THROTTLED"],
                        "destination" => ["any" => true],
                        "descr" =>
                        "WG Suite: Block over-quota peers [WGX_THROTTLED]",
                        "created" => make_config_revision_entry(),
                    ];

                    // Floating rules live under filter/rule with 'floating' = 'yes'.
                    // Prepend so it evaluates before any pass rules.
                    array_unshift($float_rules, $wgx_block_rule);
                    config_set_path("filter/rule", $float_rules);
                    write_config(
                        "WG Suite: Created WGX_THROTTLED floating block rule"
                    );
                    filter_configure();
                    syslog(
                        LOG_NOTICE,
                        "WG Suite: Created WGX_THROTTLED floating block rule."
                    );
                }
            }
            // ================================================================


            // === POST-APPLY VERIFICATION =================================
            // Everything above silently swallows errors, so confirm the peer
            // actually reached the running interface and that the interface is
            // up and listening. This turns a silent "no handshake" dead-end
            // into an actionable message and tells us which layer failed.
            $verify_warnings = [];
            $iface_listening = false;
            $peer_in_kernel  = false;
            $listen_port     = "";
            $dump            = "";

            if (!empty($wg_bin)) {
                $dump = wgx_wg_exec($wg_bin, ["show", $tun_name, "dump"]);
                if ($dump !== "") {
                    $dump_lines = explode("\n", trim($dump));
                    // First line is the interface: privkey pubkey listen-port fwmark
                    $if_parts = preg_split('/\s+/', trim($dump_lines[0]));
                    if (isset($if_parts[2]) && (int) $if_parts[2] > 0) {
                        $iface_listening = true;
                        $listen_port = $if_parts[2];
                    }
                    // Remaining lines are peers; field 0 is the peer public key
                    for ($li = 1; $li < count($dump_lines); $li++) {
                        $pk = preg_split('/\s+/', trim($dump_lines[$li]))[0] ?? "";
                        if ($pk === $publickey) {
                            $peer_in_kernel = true;
                            break;
                        }
                    }
                } else {
                    $verify_warnings[] =
                        "interface '{$tun_name}' is not up (wg show returned nothing) — the WireGuard service did not apply the tunnel";
                }
            }

            if ($dump !== "" && !$iface_listening) {
                $verify_warnings[] =
                    "interface '{$tun_name}' is up but NOT listening on a UDP port — check the tunnel's Listen Port and that the service started";
            }
            if ($iface_listening && !$peer_in_kernel) {
                $verify_warnings[] =
                    "peer was saved to config but is NOT loaded in the kernel — the package resync/apply step did not run";
            }

            // Resolve the endpoint clients will actually use.
            // For WebSocket tunnels use TCP 443, not the WireGuard UDP port.
            $verify_endpoint = "";
            $ws_tuns_check   = wgx_get_ws_tunnels();
            foreach (wgx_get_config_array("tunnel") as $vt) {
                if (is_array($vt) && ($vt["name"] ?? "") === $tun_name) {
                    $wan_ip = wgx_best_endpoint($vt);
                    if (array_key_exists($tun_name, $ws_tuns_check)) {
                        $ws_port         = $ws_tuns_check[$tun_name]["remote_port"] ?? "443";
                        $verify_endpoint = "{$wan_ip}:{$ws_port} (TCP — WebSocket transport)";
                    } else {
                        $verify_endpoint = $wan_ip . ":" .
                            ($vt["listenport"] ?? ($listen_port ?: "51820"));
                    }
                    break;
                }
            }

            // Audit log — write to dedicated file AND syslog for reliability.
            // syslog routing varies by pfSense version so we maintain our own log.
            $audit_msg = "Peer provisioned: '{$descr}' on tunnel {$tun_name}"
                . " IP={$assignedip}"
                . " tier={$peer_tier}"
                . ($peer_transport === 'websocket' ? ' transport=websocket' : '')
                . (!empty($verify_warnings) ? ' WARNINGS=' . implode(';', $verify_warnings) : '');
            syslog(LOG_NOTICE, "WG Suite: {$audit_msg}");
            wgx_audit_log($audit_msg);

            ob_end_clean();
            header("Content-Type: application/json");
            if (!empty($verify_warnings)) {
                echo json_encode([
                    "success" => true,
                    "message" =>
                    "Peer SAVED, but it may not handshake — " .
                        implode("; ", $verify_warnings) .
                        ". Clients will dial: " .
                        ($verify_endpoint ?: "(could not resolve endpoint)") .
                        " — confirm that is publicly reachable.",
                ]);
            } else {
                echo json_encode([
                    "success" => true,
                    "message" =>
                    "Peer provisioned and loaded into the kernel"
                        . ($verify_endpoint ? " (clients dial {$verify_endpoint})" : "")
                        . ".",
                ]);
            }
            wgx_ha_maybe_sync();
            exit();
        }
        // === POST: restore_tar ===
        if ($_POST["action"] === "restore_tar") {
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF validation failed.",
                ]);
                exit();
            }
            $tunName = trim($_POST["tun"] ?? "");

            if (
                empty($tunName) ||
                !in_array($tunName, wgx_valid_tunnel_names(), true) ||
                !isset($_FILES["backup_file"]) ||
                $_FILES["backup_file"]["error"] !== UPLOAD_ERR_OK
            ) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Invalid file upload or tunnel selection.",
                ]);
                exit();
            }

            $tmp_tar = $_FILES["backup_file"]["tmp_name"];

            // ── Tar-bomb guard ──────────────────────────────────────────
            // Cap the upload, then pre-scan the archive listing so a tiny
            // .tar.gz can't expand into something that fills /tmp (which
            // is RAM-backed tmpfs on pfSense). Uses the same tar binary
            // that later extracts, so the header sizes it reports are
            // exactly what extraction would write.
            $up_size = filesize($tmp_tar);
            if ($up_size === false || $up_size > 5 * 1024 * 1024) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Backup file too large (5 MB max).",
                ]);
                exit();
            }
            $scan_err = "";
            $list_proc = proc_open(
                ["/usr/bin/tar", "-tvzf", $tmp_tar],
                [1 => ["pipe", "w"], 2 => ["pipe", "w"]],
                $list_pipes
            );
            if (is_resource($list_proc)) {
                $scan_total = 0;
                $scan_count = 0;
                while (($scan_ln = fgets($list_pipes[1])) !== false) {
                    $tok = preg_split('/\s+/', trim($scan_ln));
                    if (!is_array($tok) || count($tok) < 5) {
                        continue;
                    }
                    // bsdtar: mode links owner group SIZE date... (size idx 4)
                    // GNU:    mode owner/group SIZE date...      (size idx 2)
                    $scan_size = (strpos($tok[1], "/") !== false)
                        ? (int)$tok[2]
                        : (int)$tok[4];
                    $scan_total += $scan_size;
                    $scan_count++;
                    if ($scan_count > 500 || $scan_total > 64 * 1024 * 1024) {
                        $scan_err = "Archive is too large to restore (limits: 500 files / 64 MB uncompressed).";
                        break;
                    }
                }
                fclose($list_pipes[1]);
                fclose($list_pipes[2]);
                if (proc_close($list_proc) !== 0 && $scan_err === "") {
                    $scan_err = "Could not read the archive — is it a valid .tar.gz backup?";
                }
            } else {
                $scan_err = "Could not inspect the uploaded archive.";
            }
            if ($scan_err !== "") {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => $scan_err,
                ]);
                exit();
            }
            $extract_dir = "/tmp/wgx_restore_" . bin2hex(random_bytes(8));
            if (!mkdir($extract_dir, 0700, true)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Could not create a temporary extraction directory.",
                ]);
                exit();
            }

            $tar_cmd = ["/usr/bin/tar", "-xzf", $tmp_tar, "-C", $extract_dir];
            $tar_proc = proc_open(
                $tar_cmd,
                [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]],
                $tar_pipes
            );
            if (!is_resource($tar_proc)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Failed to extract archive.",
                ]);
                exit();
            }
            fclose($tar_pipes[0]);
            fclose($tar_pipes[1]);
            fclose($tar_pipes[2]);
            if (proc_close($tar_proc) !== 0) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "Failed to safely extract archive.",
                ]);
                exit();
            }

            $conf_files = glob($extract_dir . "/*.conf");
            $processed = 0;
            $a_peers = wgx_get_config_array("peer");
            $wg_bin_path = is_executable("/usr/local/bin/wg")
                ? "/usr/local/bin/wg"
                : "/usr/bin/wg";

            foreach ($conf_files as $file) {
                $filename = basename($file, ".conf");
                $lines = file($file);
                $privkey = "";
                $ip = "";
                $psk = "";
                $peer_name = "";
                $pubkey = "";

                // Parse the config file for Keys, IP and original name
                foreach ($lines as $line) {
                    if (preg_match('/^#\s*WGX_NAME:\s*(.+)$/i', $line, $m)) {
                        $peer_name = trim($m[1]);
                    }
                    if (preg_match('/^#\s*WGX_PUB:\s*(.+)$/i', $line, $m)) {
                        $pubkey = trim($m[1]);
                    }
                    if (
                        preg_match('/^\s*PrivateKey\s*=\s*(.+)$/i', $line, $m)
                    ) {
                        $privkey = trim($m[1]);
                    }
                    if (
                        preg_match(
                            "/^\s*Address\s*=\s*([^,\s\/]+)/i",
                            $line,
                            $m
                        )
                    ) {
                        $ip = trim($m[1]);
                    }
                    if (
                        preg_match('/^\s*PresharedKey\s*=\s*(.+)$/i', $line, $m)
                    ) {
                        $psk = trim($m[1]);
                    }
                }
                if (empty($peer_name)) {
                    $peer_name = preg_replace('/_\d+$/', "", $filename);
                }

                // Clean up placeholder private keys
                if ($privkey === "<INSERT_PRIVATE_KEY_HERE>") {
                    $privkey = "";
                }

                // Mathematically derive the Public Key if not explicitly provided in older backups
                if (empty($pubkey) && !empty($privkey)) {
                    $pubkey = wgx_derive_public($wg_bin_path, $privkey);
                }

                // Reject anything that doesn't look like a WireGuard key and
                // a real IP before it reaches the config or the kernel.
                if (!preg_match('/^[A-Za-z0-9+\/]{43}=$/', $pubkey) || !is_ipaddr($ip)) {
                    continue;
                }
                if (!empty($pubkey) && !empty($ip)) {
                    $new_peer = [
                        "enabled" => "yes",
                        "tun" => $tunName,
                        "descr" => $peer_name,
                        "dynamic" => "yes",
                        "endpoint" => "",
                        "port" => "",
                        "keepalive" => "25",
                        "publickey" => $pubkey,
                        "privatekey" => $privkey,
                        "presharedkey" => $psk,
                        "allowedips" => [
                            "row" => [
                                [
                                    "address" => $ip,
                                    "mask" => "32",
                                    "descr" => "",
                                ],
                            ],
                        ],
                    ];
                    $a_peers[] = $new_peer;
                    $processed++;

                    // === INSTANT KERNEL INJECTION ===
                    $wg_args = ["set", $tunName, "peer", $pubkey];
                    if (!empty($psk)) {
                        $tmp_psk = tempnam(sys_get_temp_dir(), "wg_psk_");
                        file_put_contents($tmp_psk, $psk);
                        chmod($tmp_psk, 0600);
                        $wg_args[] = "preshared-key";
                        $wg_args[] = $tmp_psk;
                    }
                    $wg_args[] = "persistent-keepalive";
                    $wg_args[] = "25";
                    $wg_args[] = "allowed-ips";
                    $wg_args[] = $ip . "/32";
                    wgx_wg_exec($wg_bin_path, $wg_args);
                    if (isset($tmp_psk)) {
                        @unlink($tmp_psk);
                        unset($tmp_psk);
                    }
                }
            }

            // Cleanup temp directory safely
            if (is_dir($extract_dir)) {
                $files = array_diff(scandir($extract_dir), [".", ".."]);
                foreach ($files as $file) {
                    @unlink($extract_dir . "/" . $file);
                }
                @rmdir($extract_dir);
            }

            if ($processed > 0) {
                global $config;
                if (function_exists("config_set_path")) {
                    config_set_path(
                        "installedpackages/wireguard/peers/item",
                        $a_peers
                    );
                } else {
                    $config["installedpackages"]["wireguard"]["peers"]["item"] = $a_peers;
                }
                write_config(
                    "WG Suite: Restored {$processed} peers from backup."
                );
                sync_package("wireguard");
            }

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "message" => "Successfully restored and injected {$processed} peers!",
            ]);
            exit();
        }
    } catch (\Throwable $e) {
        ob_end_clean();
        header("Content-Type: application/json");
        echo json_encode([
            "success" => false,
            "message" => "PHP Error: " . $e->getMessage(),
        ]);
        exit();
    }
}

if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_GET["action"])) {
    // Accept the CSRF token via a request header so it never has to ride
    // in the URL (query strings land in webserver logs; headers do not).
    // The per-handler ?__csrf_magic= fallbacks below remain for backward
    // compatibility with cached pages, but the JS no longer uses them.
    if (!isset($_POST["__csrf_magic"]) && !empty($_SERVER["HTTP_X_WGX_CSRF"])) {
        $_POST["__csrf_magic"] = (string)$_SERVER["HTTP_X_WGX_CSRF"];
    }
    ob_start();
    try {
        // === 4.O. GET: gen_keys / gen_psk ===
        if ($_GET["action"] === "gen_keys") {
            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode(["error" => "Rate limit exceeded."]);
                exit();
            }
            $pair = wgx_gen_keypair($wg_bin);
            if (empty($pair["priv"]) || empty($pair["pub"])) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode(["error" => "Key generation failed."]);
                exit();
            }
            $psk = wgx_gen_psk_key($wg_bin);
            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            echo json_encode([
                "priv" => $pair["priv"],
                "pub" => $pair["pub"],
                "psk" => $psk,
            ]);
            exit();
        }

        if ($_GET["action"] === "gen_psk") {
            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode(["error" => "Rate limit exceeded."]);
                exit();
            }
            $psk = wgx_gen_psk_key($wg_bin);
            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            echo json_encode(["psk" => $psk]);
            exit();
        }

        // === 4.P0. GET: peer_doctor ===
        if ($_GET["action"] === "peer_doctor" && isset($_GET["peer_idx"])) {
            if (
                isset($_GET["__csrf_magic"]) &&
                !isset($_POST["__csrf_magic"])
            ) {
                $_POST["__csrf_magic"] = $_GET["__csrf_magic"];
            }
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode(["success" => false, "message" => "CSRF validation failed."]);
                exit();
            }
            if (!wgx_check_rate_limit()) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(429);
                echo json_encode(["success" => false, "message" => "Rate limit exceeded."]);
                exit();
            }
            $result = wgx_doctor_run((int)$_GET["peer_idx"], $wg_bin);
            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            echo json_encode($result);
            exit();
        }

        // === 4.P. GET: get_conf_data ===
        if ($_GET["action"] === "get_conf_data" && isset($_GET["peer_idx"])) {
            if (
                isset($_GET["__csrf_magic"]) &&
                !isset($_POST["__csrf_magic"])
            ) {
                $_POST["__csrf_magic"] = $_GET["__csrf_magic"];
            }
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode(["error" => "CSRF validation failed."]);
                exit();
            }
            $idx = (int) $_GET["peer_idx"];

            $a_tunnels = wgx_get_config_array("tunnel");
            $a_peers = wgx_get_config_array("peer");

            if (!isset($a_peers[$idx]) || !is_array($a_peers[$idx])) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(404);
                echo json_encode(["error" => "Peer not found."]);
                exit();
            }

            $peer = $a_peers[$idx];
            $server_tun = null;

            foreach ($a_tunnels as $t) {
                if (
                    is_array($t) &&
                    ($t["name"] ?? "") === ($peer["tun"] ?? "")
                ) {
                    $server_tun = $t;
                    break;
                }
            }

            if (!$server_tun) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(404);
                echo json_encode(["error" => "Tunnel not found."]);
                exit();
            }

            // If this peer is on a WebSocket tunnel, override the endpoint
            // to show the TCP address (WAN IP : WS port) rather than the
            // raw WireGuard UDP port. The peer device connects via TCP 443.
            $ws_tuns       = wgx_get_ws_tunnels();
            $peer_tun_name = $peer["tun"] ?? "";
            $is_ws_peer    = !empty($peer["wgx_ws_transport"]) || array_key_exists($peer_tun_name, $ws_tuns);
            $ws_cfg        = $ws_tuns[$peer_tun_name] ?? [];
            $wan_ip        = wgx_best_endpoint($server_tun);

            if ($is_ws_peer && !empty($ws_cfg)) {
                $ws_port     = $ws_cfg["remote_port"] ?? "443";
                $wg_udp_port = $server_tun["listenport"] ?? "51820";
                // The peer's WireGuard Endpoint must point to their LOCAL
                // wg_client_tunnel daemon (127.0.0.1:<wg_port>), not directly
                // to the pfSense server. wg_client_tunnel.php runs on the peer
                // device and wraps the UDP traffic in WebSocket frames.
                $default_ep  = "127.0.0.1:{$wg_udp_port}";
            } else {
                $ws_port     = "443";
                $wan_ip_ep   = $wan_ip . ":" . ($server_tun["listenport"] ?? "51820");
                $default_ep  = $wan_ip_ep;
            }

            $resp = [
                "template"          => wgx_build_conf_template($peer, $server_tun),
                "default_endpoint"  => $default_ep,
                "existing_psk"      => $peer["presharedkey"] ?? "",
                "existing_keepalive" => $peer["persistentkeepalive"] ?? ($peer["keepalive"] ?? "25"),
                "existing_privkey"  => $peer["privatekey"] ?? "",
                "peer_desc"         => $peer["descr"] ?? "",
                "peer_tun"          => $peer["tun"] ?? "",
                "peer_tier"         => $peer["wgx_tier"] ?? "admin",
                "peer_target"       => $peer["wgx_target"] ?? "",
                "peer_schedule"     => $peer["wgx_schedule"] ?? "always",
                "peer_autorotate"   => $peer["wgx_autorotate"] ?? "0",
                "peer_pubkey"       => $peer["publickey"] ?? "",
                "ws_transport"      => $is_ws_peer,
                "ws_server_ip"      => $is_ws_peer ? $wan_ip : "",
                "ws_server_port"    => $is_ws_peer ? ($ws_cfg["remote_port"] ?? "443") : "",
                "ws_path"           => $is_ws_peer ? ($ws_cfg["ws_path"] ?? "/tunnel") : "",
                "ws_tun_name"       => $is_ws_peer ? $peer_tun_name : "",
                "peer_email"        => $peer["wgx_email"] ?? "",
                "peer_notes"        => $peer["wgx_notes"] ?? "",
                "peer_dns_override"  => $peer["wgx_dns_override"] ?? "",
                "peer_sched_from"    => $peer["wgx_sched_from"] ?? "",
                "peer_sched_to"      => $peer["wgx_sched_to"] ?? "",
                "conf_token"         => $peer["wgx_conf_token"] ?? "",
                "conf_token_fresh"   => (time() - (int)($peer["wgx_conf_token_ts"] ?? 0)) < 86400,
                "peer_group"         => $peer["wgx_group"] ?? "",
                "offline_alert_hours" => (int)($peer["wgx_offline_alert_hours"] ?? 0),
            ];

            // --- ENTERPRISE AUDIT LOGGING ---
            $operator = $_SESSION["Username"] ?? "System";
            $client_ip = $_SERVER["REMOTE_ADDR"] ?? "Unknown";
            syslog(
                LOG_WARNING,
                "WGX AUDIT: User '{$operator}' from IP {$client_ip} exported/viewed the WireGuard configuration for peer '{$peer["descr"]}'."
            );

            // --- ONE-TIME VIEW SECURITY ENFORCEMENT ---
            if (!empty($peer["privatekey"])) {
                unset($a_peers[$idx]["privatekey"]);
                config_set_path(
                    "installedpackages/wireguard/peers/item",
                    $a_peers
                );
                write_config(
                    "WG Suite: Purged Private Key after one-time view for peer '{$peer["descr"]}'"
                );
            }

            ob_end_clean();
            header("Content-Type: application/json");
            header("Cache-Control: no-store");
            echo json_encode($resp);
            exit();
        }

        // === 4.Q.5 GET: download_ws_bundle — peer WebSocket bundle zip ===

        // === 4.R. GET: get_peer_bw — live bandwidth poll ===
        if (
            ($_GET["action"] ?? "") === "get_peer_bw" &&
            isset($_GET["pubkey"])
        ) {
            if (
                isset($_GET["__csrf_magic"]) &&
                !isset($_POST["__csrf_magic"])
            ) {
                $_POST["__csrf_magic"] = $_GET["__csrf_magic"];
            }
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF failed",
                ]);
                exit();
            }
            $req_pub = trim($_GET["pubkey"]);
            $wg_bin_bw = is_executable("/usr/bin/wg")
                ? "/usr/bin/wg"
                : "/usr/local/bin/wg";
            $rx_now = 0;
            $tx_now = 0;
            $found = false;
            $wg_out_bw = [];
            exec(
                escapeshellarg($wg_bin_bw) . " show all transfer 2>/dev/null",
                $wg_out_bw
            );
            foreach ($wg_out_bw as $bw_line) {
                $bw_parts = preg_split("/\s+/", trim($bw_line));
                if (count($bw_parts) === 4) {
                    $bw_pub = $bw_parts[1];
                    $bw_rx = (int) $bw_parts[2];
                    $bw_tx = (int) $bw_parts[3];
                } elseif (count($bw_parts) === 3) {
                    $bw_pub = $bw_parts[0];
                    $bw_rx = (int) $bw_parts[1];
                    $bw_tx = (int) $bw_parts[2];
                } else {
                    continue;
                }
                if ($bw_pub === $req_pub) {
                    $rx_now = $bw_rx;
                    $tx_now = $bw_tx;
                    $found = true;
                    break;
                }
            }
            $now_ts = microtime(true);
            $cache_bw_f = "/tmp/wgx_bw_poll.json";
            $cache_bw = file_exists($cache_bw_f)
                ? json_decode(@file_get_contents($cache_bw_f), true) ?? []
                : [];
            $prev_bw = $cache_bw[$req_pub] ?? null;
            $rx_bps = 0.0;
            $tx_bps = 0.0;
            if ($prev_bw && $found) {
                $dt = $now_ts - (float) $prev_bw["ts"];
                if ($dt >= 0.5) {
                    $rx_bps = max(0.0, ($rx_now - (int) $prev_bw["rx"]) / $dt);
                    $tx_bps = max(0.0, ($tx_now - (int) $prev_bw["tx"]) / $dt);
                }
            }
            $cache_bw[$req_pub] = [
                "rx" => $rx_now,
                "tx" => $tx_now,
                "ts" => $now_ts,
            ];
            foreach ($cache_bw as $ck => $cv) {
                if ($now_ts - (float) ($cv["ts"] ?? 0) > 600) {
                    unset($cache_bw[$ck]);
                }
            }
            @file_put_contents($cache_bw_f, json_encode($cache_bw));
            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode([
                "success" => true,
                "found" => $found,
                "rx_bytes" => $rx_now,
                "tx_bytes" => $tx_now,
                "rx_mbps" => round(($rx_bps * 8) / 1e6, 4),
                "tx_mbps" => round(($tx_bps * 8) / 1e6, 4),
                "ts" => $now_ts,
                "has_prev" => (bool) $prev_bw,
            ]);
            exit();
        }

        // === 4.T. GET: bandwidth_reports ===
        if (($_GET["action"] ?? "") === "bandwidth_reports") {
            $report_dir = '/var/db/wgx_reports';
            $files = [];
            if (is_dir($report_dir)) {
                foreach (glob($report_dir . '/wgx_bw_report_*.csv') ?: [] as $f) {
                    $files[] = [
                        'name' => basename($f),
                        'size' => filesize($f),
                        'date' => date('Y-m-d', filemtime($f)),
                    ];
                }
                usort($files, fn($a, $b) => strcmp($b['name'], $a['name']));
            }
            ob_end_clean(); header('Content-Type: application/json');
            echo json_encode(['success' => true, 'reports' => $files]);
            exit();
        }

        if (($_GET["action"] ?? "") === "download_report" && !empty($_GET["file"])) {
            $report_dir = '/var/db/wgx_reports';
            $filename = basename($_GET["file"] ?? "");
            if (!preg_match('/^wgx_bw_report_[0-9]{4}-[0-9]{2}\.csv$/', $filename)) {
                http_response_code(400); echo "Invalid filename"; exit();
            }
            $filepath = $report_dir . '/' . $filename;
            if (!file_exists($filepath)) { http_response_code(404); echo "Not found"; exit(); }
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            readfile($filepath);
            exit();
        }

        // === 4.S. GET: get_peer_history — timeline ===
        if (
            ($_GET["action"] ?? "") === "get_peer_history" &&
            isset($_GET["pubkey"])
        ) {
            if (
                isset($_GET["__csrf_magic"]) &&
                !isset($_POST["__csrf_magic"])
            ) {
                $_POST["__csrf_magic"] = $_GET["__csrf_magic"];
            }
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                echo json_encode([
                    "success" => false,
                    "message" => "CSRF failed",
                ]);
                exit();
            }
            $pubkey = trim($_GET["pubkey"] ?? "");
            $events = [];

            if (!empty($pubkey)) {
                $hist_file = '/var/db/wgx_history/' . hash('sha256', $pubkey) . '.json';
                if (file_exists($hist_file) && is_readable($hist_file)) {
                    $raw = json_decode(file_get_contents($hist_file), true) ?? [];
                    // Return newest first
                    foreach (array_reverse($raw) as $snap) {
                        $fields_html = '';
                        foreach ($snap['fields'] ?? [] as $k => $v) {
                            $fields_html .= '<span class="label label-default" style="margin-right:3px;">'
                            . htmlspecialchars(ucfirst(str_replace('_', ' ', $k)))
                            . ': ' . htmlspecialchars((string)$v) . '</span> ';
                        }
                        $user_badge = '<span class="label label-info" style="margin-right:4px;"><i class="fa fa-user"></i> '
                        . htmlspecialchars($snap['user'] ?? 'system') . '</span>';
                        $events[] = [
                            'time' => htmlspecialchars($snap['time'] ?? ''),
                            'msg'  => '<strong>' . htmlspecialchars($snap['event'] ?? '') . '</strong> '
                            . $user_badge . '<br><span style="font-size:11px;">' . $fields_html . '</span>',
                        ];
                    }
                }
            }

            // Also pull matching audit log entries for this peer
            $wgx_log = '/var/db/wgx_audit.log';
            if (!empty($pubkey) && file_exists($wgx_log) && is_readable($wgx_log)) {
                $short = substr($pubkey, 0, 12);
                $audit_raw = [];
                exec('grep -a ' . escapeshellarg($short) . ' ' . escapeshellarg($wgx_log) . ' 2>/dev/null | tail -n 50', $audit_raw);
                foreach (array_reverse($audit_raw) as $line) {
                    if (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[WG Suite\] (.+)$/', $line, $m)) {
                        $events[] = [
                            'time' => htmlspecialchars($m[1]),
                            'msg'  => '<i class="fa fa-shield text-muted"></i> ' . htmlspecialchars($m[2]),
                        ];
                    }
                }
                // Re-sort by time descending
                usort($events, function($a, $b) { return strcmp($b['time'], $a['time']); });
            }

            ob_end_clean();
            header("Content-Type: application/json");
            echo json_encode(["success" => true, "events" => $events]);
            exit();
        }

        // === 4.Q. GET: bulk_export ===
        if ($_GET["action"] === "bulk_export") {
            if (
                !isset($_POST["__csrf_magic"]) &&
                isset($_GET["__csrf_magic"])
            ) {
                $_POST["__csrf_magic"] = $_GET["__csrf_magic"];
            }
            if (!csrf_check(false)) {
                ob_end_clean();
                header("Content-Type: application/json");
                http_response_code(403);
                echo json_encode(["error" => "CSRF validation failed."]);
                exit();
            }

            $a_tunnels = wgx_get_config_array("tunnel");
            $a_peers = wgx_get_config_array("peer");

            if (
                isset($_GET["selected_peers"]) &&
                $_GET["selected_peers"] !== ""
            ) {
                $raw_indices = explode(",", $_GET["selected_peers"]);
                $peer_indices = array_filter(
                    array_map("intval", $raw_indices),
                    function ($i) use ($a_peers) {
                        return isset($a_peers[$i]);
                    }
                );
            } else {
                $peer_indices = array_keys($a_peers);
            }

            $tmp_dir = sys_get_temp_dir() . "/wgx_" . bin2hex(random_bytes(8));
            mkdir($tmp_dir, 0700);

            try {
                foreach ($peer_indices as $idx) {
                    if (!isset($a_peers[$idx]) || !is_array($a_peers[$idx])) {
                        continue;
                    }

                    $peer = $a_peers[$idx];
                    $tun_name = $peer["tun"] ?? "";
                    $server_tun = null;

                    foreach ($a_tunnels as $t) {
                        if (is_array($t) && ($t["name"] ?? "") === $tun_name) {
                            $server_tun = $t;
                            break;
                        }
                    }
                    if (!$server_tun) {
                        continue;
                    }

                    $conf = wgx_build_conf_template($peer, $server_tun);

                    $priv = !empty($peer["privatekey"])
                        ? $peer["privatekey"]
                        : "<INSERT_PRIVATE_KEY_HERE>";
                    $ep_ip = wgx_best_endpoint($server_tun);
                    $ep_port = !empty($server_tun["listenport"])
                        ? (int) $server_tun["listenport"]
                        : 51820;

                    $conf = str_replace(
                        "__PRIVATE_KEY_PLACEHOLDER__",
                        $priv,
                        $conf
                    );
                    $conf = str_replace(
                        "__ENDPOINT_PLACEHOLDER__",
                        "{$ep_ip}:{$ep_port}",
                        $conf
                    );
                    $conf = str_replace(
                        "__ALLOWEDIPS_PLACEHOLDER__",
                        "0.0.0.0/0, ::/0",
                        $conf
                    );
                    $dns_val = !empty($peer["wgx_dns_override"])
                        ? $peer["wgx_dns_override"]
                        : (!empty($wgx_settings["default_dns"]) ? $wgx_settings["default_dns"] : "8.8.8.8, 8.8.4.4");
                    $conf = str_replace(
                        "__DNS_PLACEHOLDER__",
                        "DNS = " . $dns_val,
                        $conf
                    );

                    $ka = !empty($peer["keepalive"])
                        ? $peer["keepalive"]
                        : "25";
                    $conf = str_replace(
                        "__KEEPALIVE_PLACEHOLDER__",
                        $ka,
                        $conf
                    );

                    if (!empty($peer["presharedkey"])) {
                        $conf = str_replace(
                            "__PSK_PLACEHOLDER__",
                            "PresharedKey = " . $peer["presharedkey"],
                            $conf
                        );
                    } else {
                        $conf = str_replace("__PSK_PLACEHOLDER__\n", "", $conf);
                    }

                    $safe_desc = preg_replace(
                        "/[^a-zA-Z0-9_-]/",
                        "_",
                        $peer["descr"] ?? "peer_{$idx}"
                    );
                    $safe_desc = ltrim($safe_desc, "._");
                    $filename = "{$tmp_dir}/{$safe_desc}_{$idx}.conf";

                    file_put_contents(
                        $filename,
                        "# WGX_NAME: " .
                            ($peer["descr"] ?? "") .
                            "\n# WGX_PUB: " .
                            ($peer["publickey"] ?? "") .
                            "\n" .
                            $conf
                    );
                }

                if (class_exists("ZipArchive")) {
                    $tmp_base = tempnam(sys_get_temp_dir(), "wgx_");
                    $tmp_zip = $tmp_base . ".zip";
                    $zip = new ZipArchive();
                    if ($zip->open($tmp_zip, ZipArchive::CREATE) !== true) {
                        throw new RuntimeException(
                            "Could not create ZIP archive."
                        );
                    }
                    foreach (glob("{$tmp_dir}/*.conf") as $f) {
                        $zip->addFile($f, basename($f));
                    }
                    $zip->close();

                    header("Content-Type: application/zip");
                    header(
                        'Content-Disposition: attachment; filename="wireguard_peers.zip"'
                    );
                    header("Content-Length: " . filesize($tmp_zip));
                    readfile($tmp_zip);
                    @unlink($tmp_zip);
                    @unlink($tmp_base);
                } else {
                    $tmp_base = tempnam(sys_get_temp_dir(), "wgx_");
                    $tmp_tgz = $tmp_base . ".tar.gz";
                    $tar_cmd = [
                        "/usr/bin/tar",
                        "-czf",
                        $tmp_tgz,
                        "-C",
                        $tmp_dir,
                        ".",
                    ];
                    $tar_proc = proc_open(
                        $tar_cmd,
                        [
                            0 => ["pipe", "r"],
                            1 => ["pipe", "w"],
                            2 => ["pipe", "w"],
                        ],
                        $tar_pipes
                    );
                    if (is_resource($tar_proc)) {
                        fclose($tar_pipes[0]);
                        fclose($tar_pipes[1]);
                        fclose($tar_pipes[2]);
                        proc_close($tar_proc);
                    }
                    header("Content-Type: application/gzip");
                    header(
                        'Content-Disposition: attachment; filename="wireguard_peers.tar.gz"'
                    );
                    header("Content-Length: " . filesize($tmp_tgz));
                    readfile($tmp_tgz);
                    @unlink($tmp_tgz);
                    @unlink($tmp_base);
                }
            } finally {
                foreach (glob("{$tmp_dir}/*.conf") ?: [] as $f) {
                    unlink($f);
                }
                if (is_dir($tmp_dir)) {
                    rmdir($tmp_dir);
                }
            }
            exit();
        }
    } catch (\Throwable $e) {
        ob_end_clean();
        header("Content-Type: application/json");
        echo json_encode(["error" => "PHP Error: " . $e->getMessage()]);
        exit();
    }
}

// =========================================================================
// 5.0 FRONTEND UI & LOGIC
// =========================================================================

$wg_handshakes = [];
$wg_telemetry = [];
$wg_endpoints = [];

// IP reputation cache (populated by wgx_expire.php cron when geo is enabled)
$wgx_rep_file = "/var/db/wgx_ip_reputation.json";
$wgx_reputation = file_exists($wgx_rep_file)
    ? json_decode(file_get_contents($wgx_rep_file), true) ?? []
    : [];

    if (!empty($wg_bin)) {
        // Single `wg show all dump` replaces three separate exec calls.
        // Peer line columns: iface pubkey preshared endpoint allowed-ips handshake rx tx keepalive
        $dump_raw = wgx_wg_exec($wg_bin, ["show", "all", "dump"]);
        if ($dump_raw) {
            foreach (explode("\n", $dump_raw) as $line) {
                $parts = preg_split("/\s+/", trim($line));
                // Peer lines have 9 columns; interface lines have 5 — skip those
                if (count($parts) < 9) continue;
                // Validate pubkey format before storing
                if (!preg_match('/^[A-Za-z0-9+\/]{43}=$/', $parts[1])) continue;

                $pub      = $parts[1];
                $endpoint = $parts[3];
                $hs       = (int)$parts[5];
                $rx_bytes = (float)$parts[6];
                $tx_bytes = (float)$parts[7];

                if ($hs > 0) {
                    $wg_handshakes[$pub] = $hs;
                }

                $wg_telemetry[$pub] = [
                    "rx" => round($rx_bytes / 1024 / 1024, 2),
                    "tx" => round($tx_bytes / 1024 / 1024, 2),
                ];

                if ($endpoint !== '(none)') {
                    $last_colon = strrpos($endpoint, ':');
                    $wg_endpoints[$pub] = $last_colon !== false
                    ? trim(substr($endpoint, 0, $last_colon), '[]')
                    : $endpoint;
                }
            }
        }
    }

$dynamic_split_tunnel = wgx_get_local_subnets();
$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("Export")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
include "head.inc";

$tab_array = [];
$tab_array[] = [gettext("Dashboard"), false, "/wgx/vpn_wg_dashboard.php"];
$tab_array[] = [gettext("Export"), true, "/wgx/vpn_wg_export.php"];
$tab_array[] = [gettext("Setup"), false, "/wgx/vpn_wg_setup.php"];
$tab_array[] = [gettext("Audit"), false, "/wgx/vpn_wg_audit.php"];
display_top_tabs($tab_array);

$a_peers = wgx_get_config_array("peer");

// Config integrity check — find enabled peers in config not present in kernel
$wgx_kernel_missing = [];
if (!empty($wg_handshakes) || !empty($wg_telemetry)) {
    // We have kernel data — check for config/kernel mismatches
    foreach ($a_peers as $idx => $p) {
        if (($p['enabled'] ?? 'no') !== 'yes') continue;
        $pub = $p['publickey'] ?? '';
        if (empty($pub)) continue;
        // If the peer has never had a handshake AND has zero telemetry,
        // it may simply be new — only flag it if the tunnel itself is running
        $tun = $p['tun'] ?? '';
        $tun_running = false;
        foreach ($a_tunnels as $t) {
            if (($t['name'] ?? '') === $tun && ($t['enabled'] ?? 'no') === 'yes') {
                $tun_running = true;
                break;
            }
        }
        if ($tun_running && !isset($wg_handshakes[$pub]) && !isset($wg_telemetry[$pub])) {
            $wgx_kernel_missing[] = $p['descr'] ?? "Peer {$idx}";
        }
    }
}

// Collect all unique tags for the tag filter bar
$all_tags = [];
foreach ($a_peers as $p) {
    if (!empty($p["wgx_tags"])) {
        foreach (explode(",", $p["wgx_tags"]) as $t) {
            $t = trim($t);
            if ($t !== "" && !in_array($t, $all_tags)) {
                $all_tags[] = $t;
            }
        }
    }
}
sort($all_tags);

// Sort peers by Assigned IPv4 address while preserving the original config index for UI actions
uasort($a_peers, function ($a, $b) {
    $get_ip_val = function ($p) {
        $allowedips =
            isset($p["allowedips"]) && is_array($p["allowedips"])
            ? $p["allowedips"]
            : [];
        $raw = $allowedips["row"] ?? ($allowedips["item"] ?? []);
        $rows = isset($raw["address"]) ? [$raw] : (is_array($raw) ? $raw : []);
        foreach ($rows as $row) {
            if (
                is_array($row) &&
                !empty($row["address"]) &&
                is_ipaddrv4($row["address"])
            ) {
                return ip2long($row["address"]);
            }
        }
        return 0; // Fallback value for empty or IPv6-only peers
    };
    return $get_ip_val($a) <=> $get_ip_val($b);
});

$a_tunnels = wgx_get_config_array("tunnel");

$tunnels_json = [];
foreach ($a_tunnels as $tun) {
    if (!is_array($tun)) {
        continue;
    }
    $ep_ip = wgx_best_endpoint($tun);
    $ep_port = !empty($tun["listenport"]) ? (int) $tun["listenport"] : 51820;

    // Robust subnet detection — see wgx_detect_tunnel_subnet() for the
    // full priority list (opt-iface → tun.addresses → peer inference →
    // safe default). Guarantees a non-empty base for the Assigned-IP
    // auto-picker even on tunnels missing an explicit address block.
    [$tun_base, $mask, $is_v6, $sub_src] = wgx_detect_tunnel_subnet(
        $tun,
        $a_peers,
        (array)($config["interfaces"] ?? [])
    );
    $tun_sub = $tun_base !== '' ? gen_subnet($tun_base, $mask) . "/" . $mask : '';

    $next_ip = "";
    if ($tun_base !== '') {
        $next_ip = $is_v6
            ? (wgx_allocate_ipv6($tun["name"] ?? "", $tun_base, $mask) ?? "Subnet full")
            : (wgx_allocate_ipv4($tun["name"] ?? "", $tun_base, $mask) ?? "Subnet full");
    }

    // Count current enabled peers on this tunnel for the limit check
    $tun_peer_count = 0;
    foreach ($a_peers as $_p) {
        if (($_p["tun"] ?? "") === ($tun["name"] ?? "") && ($_p["enabled"] ?? "no") === "yes") {
            $tun_peer_count++;
        }
    }
    $tunnels_json[] = [
        "name"        => $tun["name"] ?? "",
        "pubkey"      => $tun["publickey"] ?? "",
        "endpoint"    => "{$ep_ip}:{$ep_port}",
        "subnet"      => $tun_sub,
        "next_ip"     => $next_ip,
        "subnet_src"  => $sub_src,
        "peer_limit"  => (int)($tun["wgx_peer_limit"] ?? 0),
        "peer_count"  => $tun_peer_count,
    ];
}

$auto_open_idx = null;
$auto_open_name = null;
if (
    isset($_GET["provision_idx"]) &&
    ctype_digit((string) $_GET["provision_idx"])
) {
    $idx = (int) $_GET["provision_idx"];
    if (isset($a_peers[$idx]) && is_array($a_peers[$idx])) {
        $auto_open_idx = $idx;
        $auto_open_name = $a_peers[$idx]["descr"] ?? "Peer {$idx}";
    }
}

$wgx_settings  = wgx_load_settings();
$wgx_ws_tunnels = wgx_get_ws_tunnels();  // ['tun_wg1' => [...ws config...], ...]
$local_interfaces = get_configured_interface_with_descr();
?>

<style>
    @keyframes pulse {

        0%,
        100% {
            opacity: 1;
        }

        50% {
            opacity: 0.3;
        }
    }

    .status-pulse {
        animation: pulse 1.5s infinite;
        color: #5cb85c;
    }

    #qrcode_canvas img,
    #qrcode_canvas canvas {
        border-radius: 4px;
    }

    .wizard-tab {
        display: none;
    }

    .wizard-tab.active {
        display: block;
    }

    .wgx-step-pending {
        opacity: 0.6;
    }

    .wgx-step-active {
        font-weight: bold;
    }

    .wgx-step-done {
    }

    .wgx-step-fail {
    }

    .input-group-btn .btn {
        margin-bottom: 0 !important;
        border-radius: 0 4px 4px 0 !important;
    }

    .input-group-btn .dropdown-toggle {
        border-radius: 0 4px 4px 0 !important;
    }

    .btn-rot {
        background-color: #8e44ad;
        color: white;
        border-color: #732d91;
    }

    .btn-rot:hover {
        background-color: #732d91;
        color: white;
    }

    .btn-red {
        background-color: #c0392b;
        border-color: #a93226;
        color: #fff !important;
    }

    .btn-red:hover {
        background-color: #a93226;
        border-color: #922b21;
        color: #fff !important;
    }
    @media (max-width: 767px) {
        .btn-group > .btn { font-size: 11px; padding: 3px 6px; }
        #peersTable thead { display: none; }
        #peersTable tr { display: block; border-bottom: 2px solid rgba(128,128,128,0.2); padding: 6px 0; }
        #peersTable td { display: block; text-align: left !important; padding: 3px 8px; border: none; white-space: normal !important; }
        #peersTable td:before { content: attr(data-label); font-weight: 700; font-size: 10px; text-transform: uppercase; opacity: 0.55; display: block; }
        .col-sm-3, .col-sm-9 { width: 100% !important; margin-bottom: 8px; }
        .modal-dialog { margin: 5px; }
        .modal-body { padding: 10px; }
        .panel-body { padding: 10px; }
        .btn-group-top { display: flex; flex-wrap: wrap; gap: 4px; }
        .btn-group-top .btn { flex: 1 1 auto; min-width: 80px; font-size: 11px; }
        .table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    }
    </style>

    <div class="panel panel-default">
    <div class="panel-heading">
    <h2 class="panel-title"><?= gettext("WireGuard Provisioning & Export") ?></h2>
    </div>
    <div class="panel-body">
    <?php if (!empty($wgx_kernel_missing)): ?>
    <div class="alert alert-warning alert-dismissible" id="wgxIntegrityBanner" role="alert">
    <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
    <i class="fa fa-exclamation-triangle"></i>
    <strong><?= count($wgx_kernel_missing) ?> peer(s) in config but not loaded in kernel:</strong>
    <?= htmlspecialchars(implode(', ', $wgx_kernel_missing)) ?>.
    The WireGuard service may need to be restarted.
    <a href="/wg/vpn_wg_tunnels.php" class="alert-link">Check tunnel status &rarr;</a>
    </div>
    <?php endif; ?>
    <?php if (empty($a_tunnels)): ?>
    <div class="alert alert-info alert-dismissible" id="wgxFirstRunBanner" role="alert">
    <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
    <h4><i class="fa fa-rocket"></i> Welcome to WG Suite!</h4>
    No WireGuard tunnels are configured yet. Start by creating a tunnel in the
    <a href="/wgx/vpn_wg_setup.php" class="alert-link"><strong>Setup tab</strong></a>,
then come back here to provision peers.
</div>
<?php endif; ?>
<form action="vpn_wg_export.php" method="post" name="iform" id="iform" onsubmit="event.preventDefault();">

            <div class="row" style="margin-bottom:15px;">
                <div class="col-sm-3">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="fa fa-search"></i></span>
                        <input type="text" id="searchPeers" class="form-control" placeholder="Search by name, tunnel, or IP…">
                    </div>
                </div>
                <div class="col-sm-9 text-right">
                <div style="display:inline-flex; align-items:center; gap:6px; margin-right:8px; float:left; margin-top:2px;">
                    <select id="groupFilter" class="form-control input-sm" style="min-width:130px;" onchange="applyFilters()">
                        <option value="">All Groups</option>
                        <?php
                        $all_groups = array_unique(array_filter(array_map(fn($p) => $p['wgx_group'] ?? '', $a_peers)));
                        sort($all_groups);
                        foreach ($all_groups as $grp): ?>
                        <option value="<?= htmlspecialchars($grp, ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($grp, ENT_QUOTES, 'UTF-8') ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="btn-group" role="group">
                <button class="btn btn-sm btn-rot" onclick="openGlobalSettings()" title="Global Policies" style="color: #ffffff !important;">
                <i class="fa fa-cog icon-embed-btn"></i> Global Settings
                </button>
                <button class="btn btn-sm btn-primary" onclick="openCsvModal()" title="Bulk CSV Import" style="color: #ffffff !important;">
                <i class="fa fa-table icon-embed-btn"></i> Bulk CSV
                </button>
                <button class="btn btn-sm btn-info" onclick="openRestoreModal()" title="Restore from Backup" style="color: #ffffff !important;">
                <i class="fa fa-history icon-embed-btn"></i> Restore Backup
                </button>
                <button class="btn btn-sm btn-red" onclick="document.getElementById('importConfFileMain').click()" title="Upload an existing .conf file" style="color: #ffffff !important;">
                <i class="fa fa-upload icon-embed-btn"></i> Import .conf
                </button>
                <input type="file" id="importConfFileMain" style="display:none" accept=".conf,.txt" onchange="handleConfUpload(event)">
                <button class="btn btn-sm btn-success" onclick="openAddPeerModal()" title="Provision New Peer" style="color: #ffffff !important;">
                <i class="fa fa-plus icon-embed-btn"></i> Add Peer
                </button>
                <button class="btn btn-sm btn-warning" onclick="downloadAll()" title="Download All Configurations" style="color: #ffffff !important;">
                <i class="fa fa-archive icon-embed-btn"></i> Download All
                </button>
                <button class="btn btn-sm btn-primary" onclick="openHaSyncModal()" title="High-Availability Sync" style="color: #ffffff !important;">
                <i class="fa fa-refresh icon-embed-btn"></i> HA Sync
                <span id="haSyncBadge" style="display:none; margin-left:6px; padding:2px 6px; border-radius:9px; font-size:10px; font-weight:700;"></span>
                </button>
                </div>
                </div>
            </div>

            <?php if (!empty($all_tags)): ?>
                <div id="tagFilterBar" style="margin-bottom:10px;">
                    <button class="btn btn-xs btn-default tag-filter-btn active" data-tag="" onclick="filterByTag(this)">All</button>
                    <?php foreach ($all_tags as $tag): ?>
                        <button class="btn btn-xs btn-default tag-filter-btn" data-tag="<?= htmlspecialchars(
                                                                                            $tag
                                                                                        ) ?>" onclick="filterByTag(this)"><?= htmlspecialchars(
                                                    $tag
                                                ) ?></button>
                    <?php endforeach; ?>
                    <button class="btn btn-xs btn-info" style="margin-left:8px;" onclick="selectByActiveTag()" title="Select all peers with active tag"><i class="fa fa-check-square-o"></i> Select Tag</button>
                </div>
            <?php endif; ?>

            <div id="bulkToolbar" style="display:none; margin-bottom:8px;">
            <div class="btn-group">
            <button class="btn btn-xs btn-success" onclick="bulkAction('enable')"><i class="fa fa-check"></i> Enable</button>
            <button class="btn btn-xs btn-warning" onclick="bulkAction('disable')"><i class="fa fa-ban"></i> Disable</button>
            <button class="btn btn-xs btn-info" onclick="bulkAction('rotate_keys')"><i class="fa fa-refresh"></i> Rotate Keys</button>
            <button class="btn btn-xs btn-primary" onclick="downloadSelected()"><i class="fa fa-download"></i> Download Configs</button>
            <button class="btn btn-xs btn-rot" onclick="openBulkExtendModal()"><i class="fa fa-clock-o"></i> Extend Expiry</button>
            <button class="btn btn-xs btn-danger" onclick="bulkAction('delete')"><i class="fa fa-trash"></i> Delete</button>
            </div>
            <span id="bulkCount" class="text-muted" style="margin-left:10px; font-size:12px;"></span>
            </div>

            <!-- Bulk Extend Expiry Modal -->
            <div class="modal fade" id="bulkExtendModal" tabindex="-1" role="dialog">
            <div class="modal-dialog modal-sm" role="document">
            <div class="modal-content">
            <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal">&times;</button>
            <h4 class="modal-title"><i class="fa fa-clock-o"></i> Extend Expiry</h4>
            </div>
            <div class="modal-body">
            <p class="text-muted" style="margin-bottom:10px;">Extend expiry for all selected peers by:</p>
            <div class="input-group">
            <input type="number" id="bulkExtendDays" class="form-control" value="30" min="1" max="3650">
            <span class="input-group-addon">days</span>
            </div>
            <p class="text-muted" style="font-size:11px; margin-top:8px;">Peers without an expiry will have one set from today.</p>
            </div>
            <div class="modal-footer">
            <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="confirmBulkExtend()"><i class="fa fa-check"></i> Extend</button>
            </div>
            </div>
            </div>
            </div>
            <div class="table-responsive">
                <table class="table table-striped table-hover table-condensed" id="peersTable">
                    <thead>
                        <tr>
                            <th style="width: 30px; padding-left: 15px;"><input type="checkbox" id="selectAll" title="Select all"></th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Role</th>
                            <th>Tunnel</th>
                            <th>Assigned IPs</th>
                            <th class="text-center">Last Seen</th>
                            <th class="text-center">Data (Rx/Tx)</th>
                            <th class="text-center">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($a_peers)): ?>
                            <tr>
                                <td colspan="9" class="text-center">No WireGuard peers configured.</td>
                            </tr>
                            <?php
                        // Zero-Trust Tier Badges
                        // Time-Based Scheduling Badge
                        // Key Age Badge

                        // Tag badges

                        // IP Reputation badge
                        // Zero-Trust Tier Badges
                        // Time-Based Scheduling Badge
                        // Key Age Badge
                        // Tag badges
                        // IP Reputation badge
                        else: foreach ($a_peers as $idx => $peer):

                                if (!is_array($peer)) {
                                    continue;
                                }

                                $display_desc = htmlspecialchars(
                                    $peer["descr"] ?? "Peer {$idx}",
                                    ENT_QUOTES,
                                    "UTF-8"
                                );
                                $display_tun = htmlspecialchars(
                                    $peer["tun"] ?? "Unknown",
                                    ENT_QUOTES,
                                    "UTF-8"
                                );
                                $pubkey = $peer["publickey"] ?? "";

                                $tier = $peer["wgx_tier"] ?? "admin";
                                if ($tier === "admin") {
                                    $role_badge =
                                        '<span class="label label-success"><i class="fa fa-shield"></i> Admin</span>';
                                } elseif ($tier === "internet_only") {
                                    $role_badge =
                                        '<span class="label label-warning"><i class="fa fa-globe"></i> BYOD (Internet)</span>';
                                } elseif ($tier === "vendor") {
                                    $target = htmlspecialchars(
                                        $peer["wgx_target"] ?? "Unknown"
                                    );
                                    $role_badge =
                                        '<span class="label label-danger" title="Restricted to: ' .
                                        $target .
                                        '"><i class="fa fa-lock"></i> Vendor Isolated</span>';
                                } else {
                                    $role_badge =
                                        '<span class="label label-default">Legacy</span>';
                                }

                                $rx = isset($wg_telemetry[$pubkey])
                                    ? $wg_telemetry[$pubkey]["rx"]
                                    : 0;
                                $tx = isset($wg_telemetry[$pubkey])
                                    ? $wg_telemetry[$pubkey]["tx"]
                                    : 0;

                                $sched_badge =
                                    isset($peer["wgx_schedule"]) &&
                                    $peer["wgx_schedule"] !== "always"
                                    ? '<br><span class="label label-warning" style="font-size:10px;"><i class="fa fa-clock-o"></i> Schedule: ' .
                                    htmlspecialchars(
                                        ucfirst($peer["wgx_schedule"]),
                                        ENT_QUOTES,
                                        "UTF-8"
                                    ) .
                                    "</span>"
                                    : "";

                                $key_rotation_days = max(
                                    1,
                                    (int) ($wgx_settings["key_rotation_days"] ?? 90)
                                );
                                $key_created = isset($peer["key_created"])
                                    ? (int) $peer["key_created"]
                                    : null;
                                if ($key_created) {
                                    $key_age_days = (int) floor(
                                        (time() - $key_created) / 86400
                                    );
                                    $key_pct = $key_age_days / $key_rotation_days;
                                    if ($key_pct >= 1) {
                                        $key_badge_class = "label-danger";
                                        $key_badge_icon = "fa-exclamation-triangle";
                                        $key_badge_title = "Keys overdue for rotation!";
                                    } elseif ($key_pct >= 0.75) {
                                        $key_badge_class = "label-warning";
                                        $key_badge_icon = "fa-clock-o";
                                        $key_badge_title = "Keys due for rotation soon";
                                    } else {
                                        $key_badge_class = "label-success";
                                        $key_badge_icon = "fa-key";
                                        $key_badge_title = "Keys healthy";
                                    }
                                    $key_age_badge =
                                        '<br><span class="label ' .
                                        $key_badge_class .
                                        '" style="font-size:10px;" title="' .
                                        $key_badge_title .
                                        " (rotate every " .
                                        $key_rotation_days .
                                        ' days)"><i class="fa ' .
                                        $key_badge_icon .
                                        '"></i> Key: ' .
                                        $key_age_days .
                                        "d old</span>";
                                } else {
                                    $key_age_badge =
                                        '<br><span class="label label-default" style="font-size:10px;" title="Key age unknown — rotate to begin tracking"><i class="fa fa-question-circle"></i> Key age unknown</span>';
                                }

                                if (
                                    !empty($pubkey) &&
                                    isset($wg_handshakes[$pubkey]) &&
                                    $wg_handshakes[$pubkey] > 0
                                ) {
                                    $diff = time() - $wg_handshakes[$pubkey];
                                    if ($diff < 180) {
                                        $status_html =
                                            '<strong><i class="fa fa-circle status-pulse"></i> Online</strong>';
                                    } elseif ($diff < 86400) {
                                        $status_html =
                                            '<span class="text-warning"><i class="fa fa-clock-o"></i> ' .
                                            round($diff / 60) .
                                            " min ago</span>";
                                    } else {
                                        $status_html =
                                            '<span class="text-warning"><i class="fa fa-clock-o"></i> ' .
                                            round($diff / 86400) .
                                            " day(s) ago</span>";
                                    }
                                } else {
                                    $status_html =
                                        '<span class="text-muted"><i class="fa fa-circle-o"></i> Offline</span>';
                                }

                                if (
                                    isset($peer["enabled"]) &&
                                    $peer["enabled"] === "no"
                                ) {
                                    $status_html =
                                        '<span class="text-danger"><i class="fa fa-ban"></i> Disabled</span>';
                                }

                                $ip_parts = [];
                                $allowedips =
                                    isset($peer["allowedips"]) &&
                                    is_array($peer["allowedips"])
                                    ? $peer["allowedips"]
                                    : [];
                                $raw_allowedips =
                                    $allowedips["row"] ?? ($allowedips["item"] ?? []);
                                if (
                                    is_array($raw_allowedips) &&
                                    !empty($raw_allowedips)
                                ) {
                                    $rows = isset($raw_allowedips["address"])
                                        ? [$raw_allowedips]
                                        : $raw_allowedips;
                                    foreach ($rows as $row) {
                                        if (is_array($row) && !empty($row["address"])) {
                                            $ip_parts[] = htmlspecialchars(
                                                $row["address"] .
                                                    (!empty($row["mask"])
                                                        ? "/" . $row["mask"]
                                                        : ""),
                                                ENT_QUOTES,
                                                "UTF-8"
                                            );
                                        }
                                    }
                                }

                                $peer_tags = [];
                                $peer_tags_str = "";
                                if (!empty($peer["wgx_tags"])) {
                                    foreach (explode(",", $peer["wgx_tags"]) as $t) {
                                        $t = trim($t);
                                        if ($t !== "") {
                                            $peer_tags[] = $t;
                                        }
                                    }
                                }
                                $tag_colours = [
                                    "staff" => "label-primary",
                                    "contractors" => "label-warning",
                                    "iot" => "label-info",
                                    "guest" => "label-default",
                                    "admin" => "label-danger",
                                ];
                                $tag_html = "";
                                foreach ($peer_tags as $t) {
                                    $tc = $tag_colours[$t] ?? "label-default";
                                    $tag_html .=
                                        '<span class="label ' .
                                        $tc .
                                        '" style="font-size:10px;margin-right:2px;">' .
                                        htmlspecialchars($t) .
                                        "</span>";
                                }
                                if ($tag_html) {
                                    $peer_tags_str = "<br>" . $tag_html;
                                }

                                $rep_badge = "";
                                if (!empty($pubkey) && isset($wg_endpoints[$pubkey])) {
                                    $ep_raw = $wg_endpoints[$pubkey];
                                    $lc = strrpos($ep_raw, ":");
                                    $ep_ip =
                                        $lc !== false
                                        ? trim(substr($ep_raw, 0, $lc), "[]")
                                        : $ep_raw;
                                    if (
                                        isset($wgx_reputation[$ep_ip]) &&
                                        !empty($wgx_reputation[$ep_ip]["flags"])
                                    ) {
                                        $rep_flags = $wgx_reputation[$ep_ip]["flags"];
                                        $rep_isp = htmlspecialchars(
                                            $wgx_reputation[$ep_ip]["isp"] ?? ""
                                        );
                                        $rep_label = implode(
                                            " + ",
                                            array_map("strtoupper", $rep_flags)
                                        );
                                        $rep_tip =
                                            htmlspecialchars(
                                                $rep_label,
                                                ENT_QUOTES,
                                                "UTF-8"
                                            ) .
                                            ($rep_isp ? " ({$rep_isp})" : "") .
                                            " — " .
                                            htmlspecialchars($ep_ip);
                                        $rep_badge =
                                            '<br><span class="label label-danger" style="font-size:10px;" title="' .
                                            $rep_tip .
                                            '"><i class="fa fa-exclamation-triangle"></i> ' .
                                            htmlspecialchars($rep_label, ENT_QUOTES, "UTF-8") .
                                            "</span>";
                                    } elseif (isset($wgx_reputation[$ep_ip])) {
                                        $rep_isp = htmlspecialchars(
                                            $wgx_reputation[$ep_ip]["isp"] ?? ""
                                        );
                                        $rep_badge =
                                            '<br><span class="label label-success" style="font-size:10px;" title="Clean IP' .
                                            ($rep_isp ? ": {$rep_isp}" : "") .
                                            '"><i class="fa fa-shield"></i> Clean</span>';
                                    } else {
                                        $rep_badge =
                                            '<br><span class="label label-default" style="font-size:10px;" title="Rep pending for ' .
                                            htmlspecialchars($ep_ip) .
                                            '"><i class="fa fa-question-circle"></i> Rep: Pending</span>';
                                    }
                                }

                                $json_name = htmlspecialchars(json_encode(
                                    $peer["descr"] ?? "Peer {$idx}"
                                ), ENT_QUOTES, 'UTF-8');
                                $json_tags = htmlspecialchars(json_encode(
                                    $peer["wgx_tags"] ?? ""
                                ), ENT_QUOTES, 'UTF-8');
                                $json_pubkey = htmlspecialchars(json_encode(
                                    $pubkey
                                ), ENT_QUOTES, 'UTF-8');
                                $json_tun = htmlspecialchars(json_encode(
                                    $peer["tun"] ?? "Unknown"
                                ), ENT_QUOTES, 'UTF-8');
                                $json_email = htmlspecialchars(json_encode(
                                    $peer["wgx_email"] ?? ""
                                ), ENT_QUOTES, 'UTF-8');
                            ?>
                                <tr data-tags="<?= htmlspecialchars(
                                                    implode(",", $peer_tags ?? []),
                                                    ENT_QUOTES
                                                ) ?>" data-group="<?= htmlspecialchars($peer['wgx_group'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                                    <td><input type="checkbox" class="peer-checkbox" value="<?= $idx ?>"></td>
                                    <td><?= $status_html . $rep_badge ?></td>
                                    <td style="max-width:160px; word-break:break-word;"><strong><?= $display_desc ?></strong><?= $sched_badge .
                                    $key_age_badge .
                                    $peer_tags_str ?>
                                    <?php if (!empty($peer['wgx_group'])): ?>
                                    <br><span class="label label-default" style="font-size:10px; font-weight:normal;"><i class="fa fa-folder-o"></i> <?= htmlspecialchars($peer['wgx_group'], ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php endif; ?>
                                    <?php if (!empty($peer['wgx_notes'])): ?>
                                    <br><small class="text-muted" title="<?= htmlspecialchars($peer['wgx_notes'], ENT_QUOTES, 'UTF-8') ?>"><i class="fa fa-sticky-note-o"></i> <?= htmlspecialchars(mb_strimwidth($peer['wgx_notes'], 0, 40, '…'), ENT_QUOTES, 'UTF-8') ?></small>
                                    <?php endif; ?>
                                    </td>
                                    <td><?= $role_badge ?></td>
                                    <td><?= $display_tun ?></td>
                                    <td style="max-width:120px; word-break:break-word;"><?= implode("<br>", $ip_parts) ?></td>
                                    <td class="text-center" style="white-space:nowrap; font-size:12px;">
                                    <?php
                                    $hs_ts = $wg_handshakes[$pubkey] ?? 0;
                                    if ($hs_ts > 0) {
                                        $hs_diff = time() - $hs_ts;
                                        if ($hs_diff < 60)        echo '<span class="text-success"><i class="fa fa-circle"></i> ' . $hs_diff . 's ago</span>';
                                        elseif ($hs_diff < 3600)  echo '<span class="text-success"><i class="fa fa-circle"></i> ' . round($hs_diff/60) . 'm ago</span>';
                                        elseif ($hs_diff < 86400) echo '<span class="text-warning"><i class="fa fa-circle"></i> ' . round($hs_diff/3600) . 'h ago</span>';
                                        else                       echo '<span class="text-danger"><i class="fa fa-circle"></i> ' . round($hs_diff/86400) . 'd ago</span>';
                                    } else {
                                        echo '<span class="text-muted">Never</span>';
                                    }
                                    ?>
                                    </td>
                                    <td style="white-space: nowrap;" class="text-center">
                                    <i class="fa fa-arrow-down text-success"></i> <?= $rx ?>MB /
                                    <i class="fa fa-arrow-up text-info"></i> <?= $tx ?>MB
                                    </td>
                                    <td class="text-center" style="white-space: nowrap;">
                                    <div class="btn-group btn-group-xs" role="group">
                                    <button class="btn btn-xs btn-info" onclick="openExportModal(<?= $idx ?>, <?= $json_name ?>)" title="Export Config"><i class="fa fa-qrcode"></i></button>
                                    <button class="btn btn-xs btn-default" onclick="openTagEditor(<?= $idx ?>, <?= $json_tags ?>)" title="Edit Tags"><i class="fa fa-tag"></i></button>
                                    <button class="btn btn-xs btn-default" onclick="openPeerGraph(<?= $json_pubkey ?>, <?= $json_name ?>)" title="Bandwidth Graph"><i class="fa fa-bar-chart"></i></button>
                                    <button class="btn btn-xs btn-rot" onclick="rotateKeys(<?= $idx ?>, <?= $json_name ?>)" title="Rotate Keys"><i class="fa fa-refresh"></i></button>
                                    <button class="btn btn-xs btn-primary" onclick="openEmailModal(<?= $idx ?>, <?= $json_name ?>, <?= $json_email ?>)" title="Email Config"><i class="fa fa-envelope"></i></button>
                                    <button class="btn btn-xs btn-warning" onclick="killPeer(<?= $json_tun ?>, <?= $json_pubkey ?>)" title="Kill Connection"><i class="fa fa-bolt"></i></button>
                                    <button class="btn btn-xs btn-default" onclick="pingPeer(<?= json_encode(implode(',', $ip_parts)) ?>, <?= $json_name ?>, this)" title="Ping Peer"><i class="fa fa-wifi"></i></button>
                                    <button class="btn btn-xs btn-default" onclick="wgxOpenDoctor(<?= $idx ?>, <?= $json_name ?>)" title="Connectivity Doctor"><i class="fa fa-stethoscope"></i></button>
                                    <button class="btn btn-xs btn-danger" onclick="deletePeer(<?= $idx ?>, <?= $json_name ?>)" title="Delete Peer"><i class="fa fa-trash"></i></button>
                                        <?php
                                        // Show migrate button only for peers NOT already on a WS tunnel
                                        $peer_on_ws = !empty($peer["wgx_ws_transport"]) || array_key_exists($peer["tun"] ?? "", $wgx_ws_tunnels);
                                        if (!$peer_on_ws && !empty($wgx_ws_tunnels)):
                                            $ws_tun_options = htmlspecialchars(json_encode(array_keys($wgx_ws_tunnels)), ENT_QUOTES, 'UTF-8');
                                        ?>
                                            <button class="btn btn-xs btn-success"
                                                onclick="openMigrateModal(<?= $idx ?>, <?= $json_name ?>, <?= $ws_tun_options ?>)"
                                                title="Migrate to WebSocket Transport">
                                                <i class="fa fa-exchange"></i>
                                            </button>
                                        <?php elseif ($peer_on_ws): ?>
                                            <span class="label label-info" style="font-size:10px;" title="This peer uses WebSocket transport"><i class="fa fa-plug"></i> WS</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                        <?php
                            endforeach;
                        endif; ?>
                    </tbody>
                </table>
            </div>
        </form>
    </div>
    <div class="panel-footer text-right">
        <small class="text-muted">WG Suite v<?= WGX_VERSION ?> &nbsp;|&nbsp; <a href="/wgx/vpn_wg_credits.php" class="text-info" style="text-decoration: none;"><i class="fa fa-star text-warning"></i> Credits</a></small>
    </div>
</div>

<?php
// === WireGuard Status Panel Data ===
$wg_st_endpoints = [];
$wg_st_allowedips = [];
$wg_st_pubkeys = [];
if (!empty($wg_bin)) {
    $r = wgx_wg_exec($wg_bin, ["show", "all", "endpoints"]);
    if ($r) {
        foreach (explode("\n", $r) as $l) {
            $p = preg_split("/\s+/", trim($l));
            if (count($p) >= 3) {
                $wg_st_endpoints[$p[1]] = $p[2];
            }
        }
    }
    $r = wgx_wg_exec($wg_bin, [
        "show",
        "all",
        "allowed-ips",
    ]);
    if ($r) {
        foreach (explode("\n", $r) as $l) {
            $p = preg_split("/\s+/", trim($l));
            if (count($p) >= 3) {
                $wg_st_allowedips[$p[1]] = $p[2];
            }
        }
    }
    $r = wgx_wg_exec($wg_bin, [
        "show",
        "all",
        "public-key",
    ]);
    if ($r) {
        foreach (explode("\n", $r) as $l) {
            $p = preg_split("/\s+/", trim($l));
            if (count($p) >= 2) {
                $wg_st_pubkeys[$p[0]] = $p[1];
            }
        }
    }
}
function wgx_si_bytes($mb)
{
    $b = (float) $mb * 1048576;
    if ($b <= 0) {
        return "0 B";
    }
    $u = ["B", "KiB", "MiB", "GiB", "TiB"];
    $i = min((int) floor(log($b, 1024)), 4);
    return round($b / pow(1024, $i), 2) . " " . $u[$i];
}
function wgx_hs_ago($ts)
{
    if (!$ts) {
        return "(never)";
    }
    $d = time() - (int) $ts;
    if ($d < 60) {
        return $d . " seconds ago";
    }
    if ($d < 3600) {
        return round($d / 60) . " minutes ago";
    }
    if ($d < 86400) {
        return round($d / 3600) . " hours ago";
    }
    return round($d / 86400) . " days ago";
}
?>
<style>
tr[class^='treegrid-parent-'] {
    display: none;
}
</style>

<div class="panel panel-default" style="margin-top:20px;">
    <div class="panel-heading">
        <h3 class="panel-title">WireGuard Status
            <span style="float:right; font-size:12px; font-weight:normal;">
            <?php
            $wg_bin_st = is_executable('/usr/local/bin/wg') ? '/usr/local/bin/wg' : '/usr/bin/wg';
            $running_tuns = [];
            if (!empty($wg_bin_st)) {
                $st_out = []; exec(escapeshellarg($wg_bin_st) . ' show interfaces 2>/dev/null', $st_out);
                $running_tuns = preg_split('/\s+/', trim(implode(' ', $st_out)));
            }
            foreach ($a_tunnels as $st_tun):
                if (!is_array($st_tun)) continue;
                $st_name = $st_tun['name'] ?? '';
                $st_running = in_array($st_name, $running_tuns, true);
                $st_peers = 0;
                foreach ($a_peers as $sp) { if (($sp['tun'] ?? '') === $st_name && ($sp['enabled'] ?? 'no') === 'yes') $st_peers++; }
                $st_cls = $st_running ? 'text-success' : 'text-danger';
                $st_icon = $st_running ? 'fa-check-circle' : 'fa-times-circle';
            ?>
            <span style="margin-left:12px;" class="<?= $st_cls ?>">
                <i class="fa <?= $st_icon ?>"></i> <?= htmlspecialchars($st_name) ?>
                <span class="text-muted">(<?= $st_peers ?> peer<?= $st_peers !== 1 ? 's' : '' ?>)</span>
            </span>
            <?php endforeach; ?>
            </span>
        </h3>
    </div>
    <div class="table-responsive panel-body">
        <table class="table table-hover table-striped table-condensed tree" style="overflow-x:visible;">
            <thead>
                <tr>
                    <th>Tunnel</th>
                    <th>Description</th>
                    <th>Peers</th>
                    <th>Public Key</th>
                    <th>Address / Assignment</th>
                    <th>MTU</th>
                    <th>Listen Port</th>
                    <th>RX</th>
                    <th>TX</th>
                    <th style="width:70px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($a_tunnels)): ?>
                    <tr>
                        <td colspan="10" class="text-center text-muted">No WireGuard tunnels configured.</td>
                    </tr>
                    <?php else: foreach ($a_tunnels as $tun):

                        if (!is_array($tun)) {
                            continue;
                        }
                        $tn = $tun["name"] ?? "";
                        $tpub =
                            $wg_st_pubkeys[$tn] ??
                            ($tun["publickey"] ?? "");
                        $tpeer_count = 0;
                        foreach ($a_peers as $pr) {
                            if (
                                is_array($pr) &&
                                ($pr["tun"] ?? "") === $tn
                            ) {
                                $tpeer_count++;
                            }
                        }
                        $tiface_key = "";
                        $tiface_label = "";
                        foreach (
                            $config["interfaces"] ?? []
                            as $ik => $iv
                        ) {
                            if (
                                is_array($iv) &&
                                ($iv["if"] ?? "") === $tn
                            ) {
                                $tiface_key = $ik;
                                $tiface_label = htmlspecialchars(
                                    ($iv["descr"] ?? strtoupper($ik)) .
                                        " (" .
                                        strtoupper($ik) .
                                        ")"
                                );
                                break;
                            }
                        }
                        $trx = 0;
                        $ttx = 0;
                        foreach ($a_peers as $pr) {
                            if (
                                is_array($pr) &&
                                ($pr["tun"] ?? "") === $tn
                            ) {
                                $trx +=
                                    $wg_telemetry[$pr["publickey"] ?? ""]["rx"] ?? 0;
                                $ttx +=
                                    $wg_telemetry[$pr["publickey"] ?? ""]["tx"] ?? 0;
                            }
                        }
                        $up_icon =
                            ($tun["enabled"] ?? "yes") === "yes"
                            ? '<i class="fa-solid fa-arrow-up text-success" style="vertical-align:middle;" title="up"></i>'
                            : '<i class="fa-solid fa-arrow-down text-danger" style="vertical-align:middle;" title="down"></i>';
                    ?>
                        <tr class="treegrid-<?= htmlspecialchars(
                                                $tn
                                            ) ?> treegrid-expanded">
                            <td>
                                <span class="treegrid-expander fa-solid fa fa-chevron-down"></span>
                                <?= $up_icon ?>
                                <a href="/wg/vpn_wg_tunnels_edit.php?tun=<?= htmlspecialchars(
                                                                                $tn
                                                                            ) ?>"><?= htmlspecialchars($tn) ?></a>
                            </td>
                            <td><?= htmlspecialchars($tun["descr"] ?? "") ?></td>
                            <td><?= $tpeer_count ?></td>
                            <td title="<?= htmlspecialchars(
                                            $tpub
                                        ) ?>"><?= htmlspecialchars(substr($tpub, 0, 16)) ?>...</td>
                            <td>
                                <?php if ($tiface_key): ?>
                                    <i class="fa-solid fa-sitemap" style="vertical-align:middle;"></i>
                                    <a style="padding-left:3px;" href="/interfaces.php?if=<?= htmlspecialchars(
                                                                                                $tiface_key
                                                                                            ) ?>"><?= $tiface_label ?></a>
                                <?php else: ?><span class="text-muted">(none)</span><?php endif; ?>
                            </td>
                            <td><?= htmlspecialchars($tun["mtu"] ?? "1500") ?></td>
                            <td><?= htmlspecialchars(
                                    $tun["listenport"] ?? "51820"
                                ) ?></td>
                            <td><?= wgx_si_bytes($trx) ?></td>
                            <td><?= wgx_si_bytes($ttx) ?></td>
                            <td>
                                <?php if ($tiface_key): ?>
                                    <button type="button" class="btn btn-xs btn-default" disabled
                                        title="Unassign this tunnel at Interfaces > Assignments before deleting">
                                        <i class="fa fa-trash"></i></button>
                                <?php else: ?>
                                    <button type="button" class="btn btn-xs btn-danger"
                                        title="Delete tunnel <?= htmlspecialchars($tn, ENT_QUOTES) ?>"
                                        onclick="wgxDeleteTunnel('<?= htmlspecialchars($tn, ENT_QUOTES) ?>', <?= (int)$tpeer_count ?>)">
                                        <i class="fa fa-trash"></i></button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr class="treegrid-parent-<?= htmlspecialchars($tn) ?>">
                            <td style="font-weight:bold;"><span class="treegrid-indent"></span><span class="treegrid-expander"></span>Peers</td>
                            <td colspan="9" class="contains-table">
                                <table class="table table-hover table-condensed">
                                    <thead>
                                        <tr>
                                            <th>Description</th>
                                            <th>Latest Handshake</th>
                                            <th>Public Key</th>
                                            <th>Endpoint</th>
                                            <th>Allowed IPs</th>
                                            <th>RX</th>
                                            <th>TX</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php
                                        $pidx = 0;
                                        $has_peers = false;
                                        foreach ($a_peers as $global_idx => $pr):

                                            if (!is_array($pr) || ($pr["tun"] ?? "") !== $tn) {
                                                continue;
                                            }
                                            $has_peers = true;
                                            $ppub = $pr["publickey"] ?? "";
                                            $phs = $wg_handshakes[$ppub] ?? 0;
                                            $ponline = $phs && time() - $phs < 180;
                                            $hs_icon = $ponline
                                                ? '<i class="fa-solid fa-handshake text-success" style="vertical-align:middle;" title="Less than 5 minutes"></i>'
                                                : '<i class="fa-solid fa-handshake text-muted" style="vertical-align:middle;" title="No recent handshake"></i>';
                                        ?>
                                            <tr>
                                                <td><?= $hs_icon ?> <?= htmlspecialchars(
                                                                        $pr["descr"] ?? ""
                                                                    ) ?></td>
                                                <td><?= htmlspecialchars(wgx_hs_ago($phs)) ?></td>
                                                <td title="<?= htmlspecialchars(
                                                                $ppub
                                                            ) ?>"><?= htmlspecialchars(substr($ppub, 0, 16)) ?>...</td>
                                                <td><?= htmlspecialchars(
                                                        $wg_st_endpoints[$ppub] ?? "(none)"
                                                    ) ?></td>
                                                <td><a href="/wg/vpn_wg_peers_edit.php?peer=<?= $global_idx ?>"><?= htmlspecialchars(
                                                                                                                    $wg_st_allowedips[$ppub] ?? ""
                                                                                                                ) ?></a></td>
                                                <td><?= wgx_si_bytes(
                                                        $wg_telemetry[$ppub]["rx"] ?? 0
                                                    ) ?></td>
                                                <td><?= wgx_si_bytes(
                                                        $wg_telemetry[$ppub]["tx"] ?? 0
                                                    ) ?></td>
                                            </tr>
                                        <?php
                                        endforeach;
                                        if (!$has_peers): ?>
                                            <tr>
                                                <td colspan="7" class="text-center text-muted">No peers have been configured</td>
                                            </tr>
                                        <?php endif;
                                        ?>
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                <?php
                    endforeach;
                endif; ?>
            </tbody>
        </table>
    </div>
</div>

<script type="text/javascript">
    //<![CDATA[
    // Vanilla-JS TreeGrid replacement — pfSense does not ship
    // /js/jquery.treegrid.min.js, and nginx logged a 404 on every page
    // load. Uses the existing markup: tunnel rows carry class
    // "treegrid-{id}" and child rows carry "treegrid-parent-{id}".
    // Expanders (`.treegrid-expander`) toggle their sibling children.
    // The CSS rule `tr[class^='treegrid-parent-'] { display:none }` keeps
    // children hidden by default; inline `display:table-row` overrides it
    // when a row is expanded.
    (function() {
        function initTreeGrid() {
            document.querySelectorAll('table.tree').forEach(function(tree) {
                var children = {};   // id -> [child rows]
                var parents  = {};   // id -> parent row
                tree.querySelectorAll('tr').forEach(function(row) {
                    row.classList.forEach(function(cls) {
                        if (cls.indexOf('treegrid-parent-') === 0) {
                            var pid = cls.substring('treegrid-parent-'.length);
                            (children[pid] = children[pid] || []).push(row);
                        } else if (cls.indexOf('treegrid-') === 0 &&
                                   cls !== 'treegrid-expanded' &&
                                   cls !== 'treegrid-expander' &&
                                   cls !== 'treegrid-indent') {
                            var id = cls.substring('treegrid-'.length);
                            parents[id] = row;
                        }
                    });
                });
                Object.keys(parents).forEach(function(id) {
                    var parent = parents[id];
                    var expander = parent.querySelector('.treegrid-expander');
                    if (!expander) { return; }
                    // Start collapsed (matches original initialState).
                    expander.classList.remove('fa-chevron-down');
                    expander.classList.add('fa-chevron-right');
                    expander.style.cursor = 'pointer';
                    // Also make the whole first cell click-to-toggle, but
                    // let inner links keep their normal behaviour.
                    var firstCell = parent.querySelector('td');
                    if (firstCell) { firstCell.style.cursor = 'pointer'; }
                    function toggle(ev) {
                        // Don't hijack clicks on links / buttons inside
                        // the row header.
                        if (ev && ev.target) {
                            var tag = ev.target.tagName;
                            if (tag === 'A' || tag === 'BUTTON' ||
                                ev.target.closest('a,button')) { return; }
                        }
                        var isCollapsed = expander.classList.contains('fa-chevron-right');
                        var kids = children[id] || [];
                        if (isCollapsed) {
                            expander.classList.remove('fa-chevron-right');
                            expander.classList.add('fa-chevron-down');
                            kids.forEach(function(c) { c.style.display = 'table-row'; });
                        } else {
                            expander.classList.remove('fa-chevron-down');
                            expander.classList.add('fa-chevron-right');
                            kids.forEach(function(c) { c.style.display = ''; });
                        }
                    }
                    expander.addEventListener('click', function(e) {
                        e.stopPropagation();  // don't also fire the firstCell handler
                        toggle(e);
                    });
                    if (firstCell) { firstCell.addEventListener('click', toggle); }
                });
            });
        }
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initTreeGrid);
        } else {
            initTreeGrid();
        }
    })();
    //]]>
</script>

<div class="modal fade" id="globalSettingsModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-cog"></i> Global Security Policies</h4>
            </div>
            <div class="modal-body">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-shield"></i> Peer Defaults</h3>
                    </div>
                    <div class="panel-body form-horizontal">
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Default DNS Servers</label>
                            <div class="col-sm-8">
                                <input type="text" id="defaultDns" class="form-control" value="<?= htmlspecialchars(
                                                                                                    $wgx_settings["default_dns"] ?? "8.8.8.8, 8.8.4.4"
                                                                                                ) ?>">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Default Keep-Alive</label>
                            <div class="col-sm-8">
                                <input type="number" id="defaultKa" class="form-control" value="<?= htmlspecialchars(
                                                                                                    $wgx_settings["default_ka"] ?? "25"
                                                                                                ) ?>">
                                <span class="help-block">Seconds. Enter 0 to disable keep-alive on mobile peers.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Default Access Policy</label>
                            <div class="col-sm-8">
                                <select id="defaultTier" class="form-control">
                                    <option value="admin" <?= !isset(
                                                                $wgx_settings["default_tier"]
                                                            ) || $wgx_settings["default_tier"] === "admin"
                                                                ? "selected"
                                                                : "" ?>>Admin / Full Access (Pass All)</option>
                                    <option value="internet_only" <?= ($wgx_settings["default_tier"] ??
                                                                        "") ===
                                                                        "internet_only"
                                                                        ? "selected"
                                                                        : "" ?>>BYOD / Guest (Internet Only, Block LAN)</option>
                                    <option value="vendor" <?= ($wgx_settings["default_tier"] ??
                                                                "") ===
                                                                "vendor"
                                                                ? "selected"
                                                                : "" ?>>Vendor / Contractor (Strict Zero-Trust Isolated)</option>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Fallback Split Subnets</label>
                            <div class="col-sm-8">
                                <input type="text" id="fallbackSubnets" class="form-control" value="<?= htmlspecialchars(
                                                                                                        $wgx_settings["fallback_subnets"] ?? ""
                                                                                                    ) ?>">
                                <span class="help-block">Default fallback subnets used for split tunneling if dynamic local subnets aren't detected.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Enforce PSK</label>
                            <div class="col-sm-8 checkbox">
                                <label>
                                    <input type="checkbox" id="setEnforcePsk" <?= ($wgx_settings["enforce_psk"] ??
                                                                                    "") ===
                                                                                    "true"
                                                                                    ? "checked"
                                                                                    : "" ?>>
                                    <small>Force generation of Pre-Shared Key.</small>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">IP Reputation &amp; Geo</label>
                            <div class="col-sm-8 checkbox">
                                <label>
                                    <input type="checkbox" id="enableGeo" <?= ($wgx_settings["enable_geo"] ??
                                                                                "") ===
                                                                                "true"
                                                                                ? "checked"
                                                                                : "" ?>>
                                    <small>Enable IP Geolocation and Reputation lookups (Map data).</small>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="panel panel-default">
                <div class="panel-heading">
                <h3 class="panel-title"><i class="fa fa-bell"></i> Webhook Notifications</h3>
                </div>
                <div class="panel-body form-horizontal">
                <div class="form-group">
                <label class="col-sm-4 control-label">Webhook URL</label>
                <div class="col-sm-8">
                <input type="url" id="webhookUrl" class="form-control"
                placeholder="https://ntfy.sh/your-topic  or  https://hooks.slack.com/…"
                value="<?= htmlspecialchars($wgx_settings['webhook_url'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                <span class="help-block" style="margin-bottom:0;">
                Supports <a href="https://ntfy.sh" target="_blank">ntfy.sh</a> topic URLs, Slack-compatible webhooks, Discord webhooks, or any HTTP POST endpoint. Leave blank to disable.
                </span>
                </div>
                </div>
                <div class="form-group">
                <label class="col-sm-4 control-label">Notify on</label>
                <div class="col-sm-8">
                <?php
                $wh_events_cfg = explode(',', $wgx_settings['webhook_events'] ?? 'expiry,rotation,quota');
                $wh_events_cfg = array_map('trim', $wh_events_cfg);
                foreach ([
                    'expiry'   => 'Peer expiry (24h warning)',
                         'rotation' => 'Key rotation due (7 day warning)',
                         'quota'    => 'Bandwidth quota exceeded',
                         'peer_add' => 'New peer provisioned',
                ] as $ev => $label): ?>
                <div class="checkbox" style="margin-top:4px;">
                <label>
                <input type="checkbox" name="webhook_event_<?= $ev ?>"
                id="webhookEvent_<?= $ev ?>"
                <?= in_array($ev, $wh_events_cfg, true) ? 'checked' : '' ?>>
                <?= htmlspecialchars($label) ?>
                </label>
                </div>
                <?php endforeach; ?>
                </div>
                </div>
                <div class="form-group">
                <div class="col-sm-offset-4 col-sm-8">
                <button type="button" class="btn btn-default btn-sm" onclick="testWebhook()">
                <i class="fa fa-paper-plane"></i> Send Test Notification
                </button>
                <span id="webhookTestStatus" style="margin-left:8px; font-size:12px;"></span>
                </div>
                </div>
                </div>
                </div>
                <div class="panel panel-default">
                <div class="panel-heading">
                <h3 class="panel-title"><i class="fa fa-key"></i> Key Management</h3>
                </div>
                    <div class="panel-body form-horizontal">
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Key Rotation Warning</label>
                            <div class="col-sm-8">
                                <div class="input-group">
                                    <input type="number" id="keyRotationDays" class="form-control" min="1" max="3650" value="<?= htmlspecialchars(
                                                                                                                                    $wgx_settings["key_rotation_days"] ?? "90"
                                                                                                                                ) ?>">
                                    <span class="input-group-addon">days</span>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Cron Auto-Rotation Engine</label>
                            <div class="col-sm-8 checkbox">
                                <label>
                                    <input type="checkbox" id="autoCronEnable" <?= ($wgx_settings["auto_cron"] ??
                                                                                    "") ===
                                                                                    "true"
                                                                                    ? "checked"
                                                                                    : "" ?>>
                                    <small>Enable daily background task (3 AM) to check and rotate keys for peers with automatic rotation configured.</small>
                                </label>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="panel panel-default" style="margin-top:15px;">
                    <div class="panel-heading"><h4 class="panel-title"><i class="fa fa-sliders"></i> Per-Tunnel Peer Limits</h4></div>
                    <div class="panel-body form-horizontal">
                        <p class="text-muted" style="font-size:12px; margin-bottom:10px;">Set a maximum number of active peers per tunnel. Set to 0 for unlimited.</p>
                        <?php foreach ($a_tunnels as $tun): if (!is_array($tun)) continue; $tn = $tun['name'] ?? ''; ?>
                        <div class="form-group" style="margin-bottom:8px;">
                            <label class="col-sm-6 control-label" style="font-weight:normal;"><?= htmlspecialchars($tn) ?></label>
                            <div class="col-sm-6">
                                <input type="number" class="form-control input-sm tunnel-peer-limit"
                                    data-tun="<?= htmlspecialchars($tn) ?>"
                                    value="<?= (int)($tun['wgx_peer_limit'] ?? 0) ?>"
                                    min="0" max="9999" placeholder="0 = unlimited">
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
            <button class="btn btn-default" data-dismiss="modal">Cancel</button>
            <button class="btn btn-primary" onclick="saveGlobalSettings()"><i class="fa fa-save"></i> Save Policies</button>
            </div>
            </div>
            </div>
            </div>

            <div class="modal fade" id="csvModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-upload"></i> Bulk CSV Import</h4>
            </div>
            <div class="modal-body">
                <div class="alert alert-info"><i class="fa fa-info-circle"></i> Format: <code>Name, IPAddress</code> &mdash; e.g. <code>Alice, 10.0.0.51/32</code>. One peer per line. Leave IP blank to auto-allocate.</div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-cog"></i> Import Settings</h3>
                    </div>
                    <div class="panel-body form-horizontal">
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Target Tunnel</label>
                            <div class="col-sm-8">
                                <select id="csvTunnelSelect" class="form-control">
                                    <?php foreach (
                                        $tunnels_json
                                        as $t
                                    ): ?><option value="<?= htmlspecialchars(
                                                            $t["name"]
                                                        ) ?>"><?= htmlspecialchars($t["name"]) ?></option><?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">CSV Data</label>
                            <div class="col-sm-8">
                                <div style="margin-bottom:6px;">
                                    <button class="btn btn-sm btn-default" onclick="document.getElementById('csvFileInput').click();"><i class="fa fa-folder-open"></i> Upload .csv / .txt file</button>
                                    <input type="file" id="csvFileInput" style="display:none" accept=".csv,.txt" onchange="handleCsvUpload(event)">
                                </div>
                                <textarea id="csvDataInput" class="form-control" rows="8" placeholder="Alice, 10.0.0.51/32&#10;Bob, 10.0.0.52/32"></textarea>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button class="btn btn-primary" onclick="processCsv()"><i class="fa fa-upload"></i> Process Import</button>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="restoreModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-archive"></i> Restore Peers from Backup</h4>
            </div>
            <div class="modal-body">
                <div class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    Upload a <code>.tar.gz</code> or <code>.zip</code> file previously exported from WG Suite. Existing peers on the selected tunnel will not be removed.
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-cog"></i> Restore Settings</h3>
                    </div>
                    <div class="panel-body form-horizontal">
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Target Tunnel</label>
                            <div class="col-sm-8">
                                <select id="restoreTunnelSelect" class="form-control">
                                    <?php foreach (
                                        $tunnels_json
                                        as $t
                                    ): ?><option value="<?= htmlspecialchars(
                                                            $t["name"]
                                                        ) ?>"><?= htmlspecialchars($t["name"]) ?></option><?php endforeach; ?>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Backup Archive</label>
                            <div class="col-sm-8">
                                <input type="file" id="restoreFileInput" class="form-control" accept=".tar.gz,.zip">
                                <span class="help-block">.tar.gz or .zip file exported from WG Suite.</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button class="btn btn-primary" onclick="processRestore()"><i class="fa fa-upload"></i> Upload &amp; Restore</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="emailModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title" id="emailModalLabel"><i class="fa fa-envelope"></i> Email Configuration</h4>
            </div>
            <div class="modal-body">
                <div class="alert alert-info" id="emailSmtpNotice">
                    <i class="fa fa-info-circle"></i>
                    Requires SMTP configured under <strong>System &rarr; Advanced &rarr; Notifications</strong>.
                </div>
                <div id="emailWsNotice" style="display:none;" class="alert alert-warning">
                    <i class="fa fa-exclamation-triangle"></i> <strong>WebSocket Transport Peer — Email Not Available</strong><br><br>
                    pfSense's built-in email system does not support file attachments, so the peer bundle cannot be sent directly from WG Suite.<br><br>
                    <strong>To distribute this peer's configuration:</strong>
                    <ol style="margin:8px 0 0 0; padding-left:18px;">
                        <li>Click <strong>Cancel</strong> to close this modal.</li>
                        <li>Click the <strong><i class="fa fa-qrcode"></i> Export Config</strong> button on the peer's row.</li>
                        <li>Click <strong>Download Peer Bundle (.tar.gz)</strong> to save the bundle to your device.</li>
                        <li>Email the bundle to the peer using your own email client (Outlook, Gmail, etc).</li>
                    </ol>
                </div>
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-paper-plane-o"></i> Delivery Details</h3>
                    </div>
                    <div class="panel-body form-horizontal">
                        <div class="form-group">
                            <label class="col-sm-4 control-label">Recipient Email</label>
                            <div class="col-sm-8">
                                <input type="email" id="emailTarget" class="form-control" placeholder="user@domain.com">
                                <span class="help-block" id="emailPrefillNote" class="text-success" style="display:none;"><i class="fa fa-check-circle"></i> Pre-filled from peer profile.</span>
                            </div>
                        </div>
                    </div>
                </div>
                <input type="hidden" id="emailConfData">
                <input type="hidden" id="emailPeerName">
                <input type="hidden" id="emailPeerIdx">
                <input type="hidden" id="emailIsWs" value="0">
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button class="btn btn-default" onclick="downloadEmailConf()" id="btnDownloadConf" style="display:none;">
                    <i class="fa fa-download"></i> Download to Email Manually
                </button>
                <div class="clearfix"></div>
                <button class="btn btn-primary" onclick="sendEmailReq()" id="btnSendMail"><i class="fa fa-paper-plane"></i> Send Configuration</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="peerGraphModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-bar-chart"></i> <span id="peerGraphTitle"></span></h4>
            </div>
            <div class="modal-body">
                <ul class="nav nav-tabs" style="margin-bottom:15px;">
                    <li class="active"><a href="#tabBandwidth" data-toggle="tab"><i class="fa fa-tachometer"></i> Live Bandwidth</a></li>
                    <li><a href="#tabTimeline" data-toggle="tab" onclick="onTimelineTab()"><i class="fa fa-clock-o"></i> Timeline</a></li>
                </ul>
                <div class="tab-content">
                    <div class="tab-pane active" id="tabBandwidth">
                        <div class="row" style="margin-bottom:12px;">
                            <div class="col-xs-3">
                                <div class="panel panel-default" style="margin-bottom:0; text-align:center;">
                                    <div class="panel-body" style="padding:8px 4px;">
                                        <div class="text-muted" style="font-size:10px; text-transform:uppercase; font-weight:bold;">Rx Speed</div>
                                        <div id="bwStatRx" class="text-success" style="font-size:18px; font-weight:bold;">-</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-xs-3">
                                <div class="panel panel-default" style="margin-bottom:0; text-align:center;">
                                    <div class="panel-body" style="padding:8px 4px;">
                                        <div class="text-muted" style="font-size:10px; text-transform:uppercase; font-weight:bold;">Tx Speed</div>
                                        <div id="bwStatTx" class="text-info" style="font-size:18px; font-weight:bold;">-</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-xs-3">
                                <div class="panel panel-default" style="margin-bottom:0; text-align:center;">
                                    <div class="panel-body" style="padding:8px 4px;">
                                        <div class="text-muted" style="font-size:10px; text-transform:uppercase; font-weight:bold;">Total Rx</div>
                                        <div id="bwStatTotalRx" style="font-size:14px; font-weight:bold;">-</div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-xs-3">
                                <div class="panel panel-default" style="margin-bottom:0; text-align:center;">
                                    <div class="panel-body" style="padding:8px 4px;">
                                        <div class="text-muted" style="font-size:10px; text-transform:uppercase; font-weight:bold;">Total Tx</div>
                                        <div id="bwStatTotalTx" style="font-size:14px; font-weight:bold;">-</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div id="peerGraphNoData" class="alert alert-info" style="display:none;">
                            <i class="fa fa-info-circle"></i> No traffic yet. Chart appears as data flows.
                        </div>
                        <div style="position:relative; height:260px;"><canvas id="peerBandwidthChart"></canvas></div>
                        <p class="text-muted text-center" style="margin-top:6px; font-size:11px;">
                            <span id="bwPollStatus">Starting...</span> &mdash; rolling 3-min window, updates every 3s
                        </p>
                    </div>
                    <div class="tab-pane" id="tabTimeline">
                        <div id="peerTimelineLoading" class="text-center" style="padding:30px;">
                            <i class="fa fa-spinner fa-spin fa-2x text-muted"></i>
                            <p class="text-muted" style="margin-top:8px;">Loading history&hellip;</p>
                        </div>
                        <div id="peerTimelineError" class="alert alert-warning" style="display:none;"></div>
                        <div id="peerTimelineContent" style="display:none; max-height:380px; overflow-y:auto;">
                            <ul class="list-unstyled" id="peerTimelineList"></ul>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="exportModal" tabindex="-1" role="dialog" aria-labelledby="exportModalLabel" data-backdrop="static">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" onclick="closeModalAndReload()"><span>&times;</span></button>
                <h4 class="modal-title" id="exportModalLabel">WireGuard Peer</h4>
            </div>
            <div class="modal-body form-horizontal">

                <div class="panel panel-default" id="rowAddNewParams" style="display:none;">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-crosshairs"></i> Provisioning Target</h3>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Tunnel</label>
                            <div class="col-sm-9">
                                <select id="tunnelSelect" class="form-control" onchange="onTunnelChange()"></select>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Description</label>
                            <div class="col-sm-9">
                            <input id="peerDescription" type="text" class="form-control" placeholder="e.g. Alice's iPhone" oninput="updateDisplays(); checkDuplicateName(this.value);">
                                <div id="peerNameDupWarn" class="alert alert-warning" style="display:none; padding:6px 10px; margin-top:5px; margin-bottom:0; font-size:12px;"><i class="fa fa-exclamation-triangle"></i> A peer with this name already exists.</div>
                            </div>
                            </div>
                            <div class="form-group">
                            <label class="col-sm-3 control-label">Group
                            <span class="text-muted" style="font-weight:normal; font-size:11px;"><br>(optional)</span>
                            </label>
                            <div class="col-sm-9">
                                <input id="peerGroup" type="text" class="form-control" placeholder="e.g. Family, Contractors, Remote Sites" list="peerGroupSuggestions">
                                <datalist id="peerGroupSuggestions"></datalist>
                                <span class="help-block" style="margin-bottom:0; font-size:11px;">Groups peers together in the table for easier management.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Notes
                            <span class="text-muted" style="font-weight:normal; font-size:11px;"><br>(admin only)</span>
                            </label>
                            <div class="col-sm-9">
                            <textarea id="peerNotes" class="form-control" rows="2" placeholder="Internal memo — never exported to peer config"></textarea>
                            </div>
                            </div>
                            <div class="form-group">
                            <label class="col-sm-3 control-label">Email Address
                                <span class="text-muted" style="font-weight:normal; font-size:11px;"><br>(optional)</span>
                            </label>
                            <div class="col-sm-9">
                                <input id="peerEmail" type="email" class="form-control" placeholder="peer@example.com">
                                <span class="help-block" style="margin-bottom:0;">Pre-fills the email field when sending the configuration. Required for WebSocket peers to receive their bundle by email.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Access Policy</label>
                            <div class="col-sm-9">
                                <select id="peerTier" class="form-control" onchange="toggleZeroTrustTarget()">
                                    <option value="admin">Admin / Full Access (Pass All)</option>
                                    <option value="internet_only">BYOD / Guest (Internet Only, Block LAN)</option>
                                    <option value="vendor">Vendor / Contractor (Strict Zero-Trust Isolated)</option>
                                </select>
                            </div>
                        </div>

                        <div class="form-group" id="zeroTrustTargetWrap" style="display:none; background-color: rgba(217, 83, 79, 0.1); padding: 10px 0; border-radius: 4px; border-left: 3px solid #d9534f;">
                            <label class="col-sm-3 control-label text-danger">Allowed Target</label>
                            <div class="col-sm-9">
                                <input id="peerTarget" type="text" class="form-control" placeholder="e.g., 10.0.0.50 or 'Server_Alias'">
                                <span class="help-block" style="margin-bottom:0;"><strong>Default Deny Active:</strong> Peer will be blocked from everything EXCEPT this specific IP, Subnet, or pfSense Alias.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Assigned IP(s)</label>
                            <div class="col-sm-9">
                                <input id="peerAssignedIP" type="text" class="form-control" placeholder="e.g. 10.10.10.5/32" oninput="updateDisplays()">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Temporary Peer</label>
                            <div class="col-sm-9">
                                <select id="peerExpiryPreset" class="form-control" onchange="wgxUpdateExpiry(this.value)">
                                    <option value="0">Permanent (no expiry)</option>
                                    <optgroup label="Short-term">
                                        <option value="1">1 Day</option>
                                        <option value="2">2 Days</option>
                                        <option value="3">3 Days</option>
                                        <option value="7">1 Week</option>
                                        <option value="14">2 Weeks</option>
                                    </optgroup>
                                    <optgroup label="Medium-term">
                                        <option value="30">1 Month</option>
                                        <option value="60">2 Months</option>
                                        <option value="90">3 Months</option>
                                    </optgroup>
                                    <optgroup label="Long-term">
                                        <option value="180">6 Months</option>
                                        <option value="365">1 Year</option>
                                    </optgroup>
                                    <option value="custom">Custom date...</option>
                                </select>
                                <div id="peerExpiryCustomRow" style="display:none; margin-top:6px;">
                                    <input type="date" id="peerExpiryCustomDate" class="form-control"
                                        min="<?= date(
                                                    "Y-m-d",
                                                    strtotime("+1 day")
                                                ) ?>"
                                        placeholder="Select expiry date">
                                    <span class="help-block" style="margin-bottom:0;">Peer will be automatically disabled at midnight on this date.</span>
                                </div>
                                <div id="peerExpiryInfo" style="display:none; margin-top:4px;" class="help-block">
                                    <i class="fa fa-clock-o text-warning"></i> <span id="peerExpiryInfoText"></span> — peer auto-disabled by WG Suite cron.
                                </div>
                                <input type="hidden" id="peerExpiryDate" value="0">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Data Quota</label>
                            <div class="col-sm-9">
                                <select id="peerQuotaPreset" class="form-control" onchange="wgxUpdateQuota(this.value)">
                                    <option value="exempt">Unlimited (exempt from quota)</option>
                                    <optgroup label="Predefined limits">
                                        <option value="1">1 GB</option>
                                        <option value="5">5 GB</option>
                                        <option value="10">10 GB</option>
                                        <option value="25">25 GB</option>
                                        <option value="50">50 GB</option>
                                        <option value="100">100 GB</option>
                                        <option value="250">250 GB</option>
                                        <option value="500">500 GB</option>
                                        <option value="1000">1 TB</option>
                                    </optgroup>
                                    <option value="global">Use global limit (<?= htmlspecialchars(
                                                                                    $wgx_settings["quota_limit_gb"] ?? "100"
                                                                                ) ?> GB)</option>
                                </select>
                                <span class="help-block" style="margin-bottom:0;">
                                    A firewall block rule and the <code>WGX_THROTTLED</code> alias are created automatically when you save a peer with a quota. Over-quota peers are blocked until their usage resets or they are made exempt. No manual firewall configuration required.
                                </span>
                                <input type="hidden" id="peerQuotaExempt" value="1">
                                <input type="hidden" id="peerQuotaLimit" value="0">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Access Schedule</label>
                            <div class="col-sm-9">
                                <select id="peerSchedule" class="form-control">
                                    <option value="always">Always On (24/7)</option>
                                    <option value="business">Business Hours (M-F, 09:00-17:00)</option>
                                    <option value="weekend">Weekends Only (Sat-Sun)</option>
                                    <option value="date_range">Date Range (custom from/to dates)</option>
                                </select>
                                <div id="dateRangeWrap" style="display:none; margin-top:8px;">
                                    <div class="row">
                                        <div class="col-sm-6">
                                            <label style="font-weight:normal; font-size:12px;">Active from</label>
                                            <input type="date" id="schedDateFrom" class="form-control input-sm">
                                        </div>
                                        <div class="col-sm-6">
                                            <label style="font-weight:normal; font-size:12px;">Active until</label>
                                            <input type="date" id="schedDateTo" class="form-control input-sm">
                                        </div>
                                    </div>
                                    <span class="help-block" style="font-size:11px; margin-bottom:0;">Peer will be automatically enabled/disabled by cron within this date range.</span>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Offline Alert
                                <span class="text-muted" style="font-weight:normal; font-size:11px;"><br>(hours)</span>
                            </label>
                            <div class="col-sm-9">
                                <input id="peerOfflineAlert" type="number" class="form-control" value="0" min="0" max="720" placeholder="0 = disabled">
                                <span class="help-block" style="margin-bottom:0; font-size:11px;">Show an alert badge on the dashboard if this peer has been offline for longer than this many hours. 0 = disabled.</span>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Auto-Rotate Keys</label>
                            <div class="col-sm-9">
                                <select id="peerAutoRotate" class="form-control">
                                    <option value="0">Disabled (Manual Only)</option>
                                    <option value="30">Every 30 Days</option>
                                    <option value="90">Every 90 Days</option>
                                    <option value="180">Every 180 Days</option>
                                    <option value="365">Annually</option>
                                </select>
                                <span class="help-block" style="margin-bottom:0;">Requires Global Engine. User will need to re-scan QR code after automatic rotation.</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="panel panel-default" id="rowKeyParams">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-key"></i> Cryptography</h3>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Client Public Key</label>
                            <div class="col-sm-9">
                                <input id="clientPubKey" type="text" class="form-control" readonly>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Client Private Key</label>
                            <div class="col-sm-9">
                                <div class="input-group">
                                    <input id="clientPrivKey" type="text" class="form-control" placeholder="Paste private key to unlock QR…" oninput="updateDisplays()">
                                    <span class="input-group-btn" id="btnWrapGenKeys" style="display:none;"><button class="btn btn-warning" onclick="refreshKeys()" title="Generate new keypair"><i class="fa fa-refresh"></i></button></span>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">
                                <span id="pskCheckboxWrapper" style="display:none;"><input type="checkbox" id="pskEnabled" onchange="togglePsk(this)"></span> Pre-Shared Key
                            </label>
                            <div class="col-sm-9">
                                <div class="input-group">
                                    <input id="clientPsk" type="text" class="form-control" oninput="updateDisplays()">
                                    <span class="input-group-btn" id="btnWrapGenPsk" style="display:none;"><button class="btn btn-warning" id="refreshPskBtn" onclick="refreshPsk()" disabled title="Generate PSK"><i class="fa fa-refresh"></i></button></span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="panel panel-default" id="rowRouteParams">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-sitemap"></i> Network & Routing</h3>
                    </div>
                    <div class="panel-body">
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Allowed IPs</label>
                            <div class="col-sm-9">
                                <div class="input-group">
                                    <input id="clientAllowedIPs" type="text" class="form-control" value="0.0.0.0/0, ::/0" oninput="updateDisplays()">
                                    <div class="input-group-btn">
                                        <button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false"><span class="caret"></span></button>
                                        <ul class="dropdown-menu dropdown-menu-right">
                                            <li><a href="#" onclick="setClientAllowedIPs('0.0.0.0/0, ::/0'); return false;">Full Tunnel (All Traffic)</a></li>
                                            <li><a href="#" onclick="setSplitTunnel(); return false;">Split Tunnel (LAN Only)</a></li>
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Endpoint Override</label>
                            <div class="col-sm-9">
                                <input id="endpointOverride" type="text" class="form-control" placeholder="host:port" oninput="updateDisplays()">
                            </div>
                        </div>
                        <div class="form-group" id="rowDnsParams">
                            <label class="col-sm-3 control-label">DNS Servers</label>
                            <div class="col-sm-9">
                                <input id="peerDNS" type="text" class="form-control" placeholder="e.g. 1.1.1.1, 8.8.8.8" oninput="updateDisplays()">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Keep Alive</label>
                            <div class="col-sm-9">
                                <input id="peerKeepAlive" type="number" class="form-control" placeholder="25" value="25" oninput="updateDisplays()">
                            </div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">WebSocket Override
                                <span class="text-muted" style="font-weight:normal;font-size:11px;"><br>(per-peer)</span>
                            </label>
                            <div class="col-sm-9">
                                <div class="checkbox" style="margin-top:0; margin-bottom:6px;">
                                    <label>
                                        <input type="checkbox" id="peerWsOverride" onchange="document.getElementById('peerWsOverrideFields').style.display=this.checked?'':'none';">
                                        Override tunnel-level WebSocket server for this peer
                                    </label>
                                </div>
                                <div id="peerWsOverrideFields" style="display:none;">
                                    <div class="row">
                                        <div class="col-sm-7">
                                            <input type="text" id="peerWsRemoteIp" class="form-control input-sm" placeholder="Remote server IP (e.g. 203.0.113.51)">
                                        </div>
                                        <div class="col-sm-2">
                                            <input type="number" id="peerWsRemotePort" class="form-control input-sm" placeholder="Port" value="443" min="1" max="65535">
                                        </div>
                                        <div class="col-sm-3">
                                            <input type="text" id="peerWsPath" class="form-control input-sm" placeholder="/tunnel">
                                        </div>
                                    </div>
                                    <span class="help-block" style="margin-top:4px; font-size:11px;">
                                        Only set this if this peer needs a different WebSocket server than the tunnel default.
                                        Leave blank to inherit the tunnel-level setting.
                                    </span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title"><i class="fa fa-file-text-o"></i> Configuration Output</h3>
                    </div>
                    <div class="panel-body">

                        <!-- Configuration output (QR + conf text) -->
                        <div id="standardOutputPanel">
                            <div class="row">
                                <div class="col-sm-4 text-center" id="qrContainerWrapper">
                                    <p><strong>Mobile QR Code</strong></p>
                                    <div id="qrcode_canvas" style="display:inline-block;padding:15px;border-radius:5px;background:#fff;min-height:120px;width:100%;"></div>
                                </div>
                                <div class="col-sm-8" id="confTextWrapper">
                                    <p style="margin-bottom: 5px;">
                                        <strong>Configuration File</strong>
                                        <span id="exportFmtToggle" style="display:none;"></span>
                                    </p>
                                    <div style="position:relative;">
                                        <textarea id="confText" class="form-control" rows="10" readonly style="font-family:monospace;font-size:12px;resize:vertical;"></textarea>
                                        <button onclick="copyConfToClipboard()" title="Copy to clipboard" style="position:absolute;top:6px;right:8px;z-index:10;" class="btn btn-xs btn-default"><i class="fa fa-clipboard"></i></button>
                                    </div>
                                    <div id="qrExpiryNotice" style="display:none;" class="alert alert-warning" style="padding:5px 10px; margin:6px 0; font-size:12px;"><i class="fa fa-clock-o"></i> This config was generated over 24 hours ago — consider rotating keys before distributing.</div>
                                    <br>
                                    <div class="row">
                                        <div class="col-sm-6" id="btnWrapDownload"><button class="btn btn-primary btn-block" onclick="downloadConfFile()"><i class="fa fa-download icon-embed-btn"></i> Download .conf File</button></div>
                                        <div class="col-sm-6" id="btnWrapAddPeer" style="display:none;"><button class="btn btn-success btn-block" id="btnAddPeer" onclick="addPeerToTunnel()"><i class="fa fa-save icon-embed-btn"></i> Provision & Save</button></div>
                                    </div>
                                </div>
                            </div>
                        </div>


                    </div>
                </div>
            </div>
            <div class="modal-footer"><button class="btn btn-default" onclick="closeModalAndReload()">Close</button></div>
        </div>
    </div>
</div>

<div class="modal fade" id="doctorModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog" role="document" style="max-width:640px;">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title"><i class="fa fa-stethoscope"></i> Connectivity Doctor — <span id="doctorPeerName"></span></h4>
            </div>
            <div class="modal-body">
                <div id="doctorSpinner" class="text-center text-muted" style="padding:26px 0;">
                    <i class="fa fa-circle-o-notch fa-spin fa-2x"></i><br>
                    <span style="font-size:12px;">Walking the connectivity chain… (the MTU probe can take a few seconds)</span>
                </div>
                <div id="doctorResults" style="display:none;">
                    <div id="doctorChecks"></div>
                    <div id="doctorNext" class="alert" style="margin:12px 0 0; padding:10px; font-size:12px;"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-sm btn-default" id="doctorRerun"><i class="fa fa-refresh"></i> Run again</button>
                <button type="button" class="btn btn-sm btn-primary" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="migrateModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-exchange"></i> Migrate Peer to WebSocket Transport</h4>
            </div>
            <div class="modal-body">
                <div class="alert alert-info">
                    <i class="fa fa-info-circle"></i>
                    This moves <strong id="migratePeerName"></strong> from its current standard WireGuard
                    tunnel to a WebSocket-enabled tunnel. Keys, IP assignment and settings are preserved.
                    The peer device will need a new config — the endpoint will become your WAN IP on TCP 443.
                </div>
                <div class="form-group">
                    <label class="control-label">Target WebSocket Tunnel</label>
                    <select id="migrateTunSelect" class="form-control"></select>
                </div>
                <div id="migrateResult" style="display:none;">
                    <span id="migrateResultText"></span>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Cancel</button>
                <button class="btn btn-success" id="btnConfirmMigrate" onclick="confirmMigrate()">
                    <i class="fa fa-exchange"></i> Migrate
                </button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="haSyncModal" tabindex="-1" role="dialog" data-backdrop="static">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <button class="close" data-dismiss="modal"><span>&times;</span></button>
                <h4 class="modal-title"><i class="fa fa-refresh"></i> HA Sync &mdash; WireGuard High Availability</h4>
            </div>
            <div class="modal-body">
                <div class="alert alert-info" style="font-size:13px;">
                    <i class="fa fa-info-circle"></i>
                    Synchronise WireGuard tunnels, peers and WGX settings from this box to a
                    <strong>backup pfSense</strong> that also runs WG Suite. If this box fails,
                    the backup can serve the same peer list. Same-network vs remote-location
                    is auto-detected from the backup IP.
                </div>

                <!-- Bootstrap allow-rule panel ------------------------------------- -->
                <div class="panel panel-warning" id="haBootstrapPanel" style="margin-bottom:16px;">
                    <div class="panel-heading" style="cursor:pointer; user-select:none;" onclick="haBootstrapToggle()">
                        <span class="panel-title" style="font-weight:600;">
                            <i class="fa fa-shield-halved fa-shield"></i>
                            Can't reach the backup? &mdash; do this on the <em>OTHER</em> box first
                            <i id="haBootstrapChevron" class="fa fa-chevron-down" style="float:right; margin-top:2px;"></i>
                        </span>
                    </div>
                    <div id="haBootstrapBody" class="panel-body" style="display:none;">
                        <p style="font-size:13px; margin-bottom:6px;">
                            If Test Connection is timing out even though the port is right, the
                            <strong>backup's WAN firewall</strong> is blocking XMLRPC from the primary.
                            One click fixes it &mdash; but the click has to happen <strong>on the backup</strong>.
                        </p>
                        <ol style="font-size:13px; margin-bottom:8px;">
                            <li>Log into the <strong>backup</strong> pfSense (the one you're trying to sync to).</li>
                            <li>Open <strong>VPN &raquo; WG Suite &raquo; Export</strong> and click <strong>HA Sync</strong> in the toolbar.</li>
                            <li>Expand this same panel there, enter the <strong>PRIMARY's IP</strong> below, and click <em>Add allow rule</em>.</li>
                            <li>Come back to the primary and hit <strong>Test Connection</strong> &mdash; it should now succeed.</li>
                        </ol>
                        <div class="alert alert-default" style="font-size:12px; padding:6px 10px; margin-bottom:10px;">
                            <i class="fa fa-lightbulb-o"></i>
                            The button below acts on <strong>this box</strong>. It creates a WAN pass rule that
                            allows the primary's IP to reach this box's web-UI port over TCP. The rule is tagged
                            <code>WGX:</code> so it will be included in future syncs.
                        </div>
                        <div class="form-horizontal">
                            <div class="form-group" style="margin-bottom:6px;">
                                <label class="col-sm-4 control-label" style="font-weight:normal;">Primary's IP or CIDR</label>
                                <div class="col-sm-8">
                                    <input type="text" id="haBootstrapIp" class="form-control input-sm" placeholder="e.g. 10.10.64.100 &nbsp;or&nbsp; 203.0.113.0/24">
                                    <span class="help-block" style="margin-bottom:0; font-size:11px;">Whatever IP the primary will connect <em>from</em> (its WAN if remote, its LAN if same network). A /24 or narrower CIDR is accepted too.</span>
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom:6px;">
                                <label class="col-sm-4 control-label" style="font-weight:normal;">Web-UI port on this box</label>
                                <div class="col-sm-8">
                                    <input type="number" id="haBootstrapPort" class="form-control input-sm" min="1" max="65535" placeholder="auto-detect this box's port">
                                    <span class="help-block" style="margin-bottom:0; font-size:11px;">Leave blank to use this box's current web-UI port.</span>
                                </div>
                            </div>
                            <div class="form-group" style="margin-bottom:0;">
                                <div class="col-sm-offset-4 col-sm-8">
                                    <button id="haBootstrapBtn" class="btn btn-warning" onclick="haBootstrapAllow()">
                                        <i class="fa fa-plus"></i> Add allow rule to this box's WAN
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="form-horizontal">
                    <div class="form-group">
                        <label class="col-sm-3 control-label">Enable HA Sync</label>
                        <div class="col-sm-9">
                            <div class="checkbox" style="margin-top:6px;">
                                <label><input type="checkbox" id="haEnabled"> Sync WGX state to the backup</label>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">Backup pfSense IP</label>
                        <div class="col-sm-6">
                            <input type="text" id="haRemoteIp" class="form-control" placeholder="e.g. 192.168.1.101 or vpn.example.com" onchange="haDetectSameNetwork()">
                            <span id="haNetworkHint" class="help-block" style="margin-bottom:0; font-size:11px;"></span>
                        </div>
                        <div class="col-sm-3">
                            <label class="control-label" style="font-weight:normal; font-size:12px;">HTTPS port</label>
                            <input type="number" id="haRemotePort" class="form-control input-sm" value="443" min="1" max="65535">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">Admin username</label>
                        <div class="col-sm-9">
                            <input type="text" id="haRemoteUser" class="form-control" value="admin">
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">Admin password</label>
                        <div class="col-sm-9">
                            <input type="password" id="haRemotePass" class="form-control" autocomplete="new-password" placeholder="Leave blank to keep existing">
                            <span class="help-block" style="margin-bottom:0; font-size:11px;">Stored base64-encoded in config.xml (same as pfSense's own hasync).</span>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">TLS certificate</label>
                        <div class="col-sm-9">
                            <div class="checkbox" style="margin:0;">
                                <label><input type="checkbox" id="haVerifyTls"> Verify backup's TLS certificate</label>
                            </div>
                            <span class="help-block" style="margin-bottom:0; font-size:11px;">Default: <strong>on</strong> for remote hosts, <strong>off</strong> for same-network (pfSense's default cert is self-signed).</span>
                        </div>
                    </div>

                    <hr>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">What to sync</label>
                        <div class="col-sm-9">
                            <div class="checkbox" style="margin:0;">
                                <label><input type="checkbox" id="haSyncWgPackage" checked> WireGuard tunnels &amp; peers (installedpackages/wireguard)</label>
                            </div>
                            <div class="checkbox" style="margin:0;">
                                <label><input type="checkbox" id="haSyncWgxSettings" checked> WGX settings (except HA Sync&nbsp;itself)</label>
                            </div>
                            <div class="checkbox" style="margin:0;">
                                <label><input type="checkbox" id="haSyncFwRules" checked> WGX-managed firewall rules (descr <code>WGX:</code> / <code>WG Suite</code>)</label>
                            </div>
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-sm-3 control-label">Trigger</label>
                        <div class="col-sm-9">
                            <div class="checkbox" style="margin:0;">
                                <label><input type="checkbox" id="haAutoSync" checked> Automatically sync after peer add / delete / rotate / bulk actions</label>
                            </div>
                            <span class="help-block" style="margin-bottom:0; font-size:11px;">Manual sync is always available via the button below.</span>
                        </div>
                    </div>

                    <div id="haLastSync" class="alert alert-default" style="display:none; font-size:12px; padding:6px 10px; margin-top:0;"></div>
                </div>

                <div id="haStepsPanel" class="panel panel-default" style="display:none; margin-top:10px;">
                    <div class="panel-heading" style="padding:8px 12px;">
                        <strong id="haStepsTitle"><i class="fa fa-stethoscope"></i> Test result</strong>
                    </div>
                    <ul id="haStepsList" class="list-group"></ul>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-default" data-dismiss="modal">Close</button>
                <button class="btn btn-info"    id="haBtnTest"  onclick="haTestConnection()"><i class="fa fa-plug"></i> Test Connection</button>
                <button class="btn btn-primary" id="haBtnSave"  onclick="haSaveSettings()"><i class="fa fa-save"></i> Save Settings</button>
                <button class="btn btn-success" id="haBtnSync"  onclick="haSyncNow()" disabled><i class="fa fa-refresh"></i> Sync Now</button>
            </div>
        </div>
    </div>
</div>

<script src="/wg_qrcode.js"></script>

<script>
    const tunnelsData = <?= json_encode(
                            $tunnels_json,
                            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
                        ) ?>;
    const wsTunnels = <?= json_encode(
                            array_keys($wgx_ws_tunnels),
                            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
                        ) ?>;
    const dynamicSplit = "<?= htmlspecialchars(
                                $dynamic_split_tunnel,
                                ENT_QUOTES,
                                "UTF-8"
                            ) ?>";
    let rawTemplateText = "";
    let defaultEndpoint = "";
    let currentPeerName = "";
    let modalMode = "export";
    let exportFormat = "client";

    function getCsrf() {
        if (typeof csrfMagicToken !== 'undefined') {
            return csrfMagicToken;
        }
        const el = document.querySelector("input[name='__csrf_magic']");
        return el ? el.value : '';
    }

    // ── HA Sync ─────────────────────────────────────────────────────────────
    // Modal-driven. Server keeps everything under installedpackages/wgexport/
    // config/0/ha_sync. Passwords never come back to the browser after
    // save — leaving the field blank on save preserves the stored password.
    var wgxHaLoaded = false;

    function openHaSyncModal() {
        haLoadSettings().then(function() {
            wgxHaLoaded = true;
            $('#haSyncModal').modal('show');
        });
    }

    function haLoadSettings() {
        return fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=ha_status&__csrf_magic=' + encodeURIComponent(getCsrf())
        }).then(function(r) { return r.json(); })
          .then(function(s) {
            // ── Fully populate the modal from the persisted settings ──
            // Every non-secret field survives a save-close-reopen cycle.
            // The password field stays blank; blank means "keep existing".
            document.getElementById('haEnabled').checked          = !!s.enabled;
            document.getElementById('haRemoteIp').value           = s.remote_ip     || '';
            // Port default: whatever was saved, else the primary's own
            // web-UI port (best guess for the backup in the same shop),
            // else 443.
            var savedPort = parseInt(s.remote_port, 10);
            var localPort = parseInt(s.local_webui_port, 10);
            document.getElementById('haRemotePort').value =
                (savedPort > 0 ? savedPort : (localPort > 0 ? localPort : 443));
            document.getElementById('haRemoteUser').value         = s.remote_user   || 'admin';
            document.getElementById('haRemotePass').value         = '';
            document.getElementById('haRemotePass').placeholder   =
                s.has_password ? 'Leave blank to keep existing' : 'Enter admin password';
            var tls = document.getElementById('haVerifyTls');
            tls.checked = !!s.verify_tls;
            tls.dataset.userSet = '1';   // stop haDetectSameNetwork from stomping it
            document.getElementById('haSyncWgPackage').checked    = s.sync_wg_package   !== false;
            document.getElementById('haSyncWgxSettings').checked  = s.sync_wgx_settings !== false;
            document.getElementById('haSyncFwRules').checked      = s.sync_fw_rules     !== false;
            document.getElementById('haAutoSync').checked         = s.auto_sync         !== false;
            // Update the network hint next to the IP field.
            haDetectSameNetwork();

            // Populate the last-sync banner.
            var el = document.getElementById('haLastSync');
            if (s.last_sync && s.last_sync > 0) {
                var when = new Date(s.last_sync * 1000).toLocaleString();
                var cls  = s.last_status === 'success' ? 'alert-success'
                         : s.last_status === 'failed'  ? 'alert-danger' : 'alert-default';
                el.className = 'alert ' + cls;
                el.style.display = '';
                el.innerHTML = '<strong>Last sync:</strong> ' + when +
                               ' &mdash; ' + (s.last_status || 'unknown') +
                               (s.last_error ? ' <span class="text-muted">(' + s.last_error + ')</span>' : '');
            } else {
                el.style.display = 'none';
            }
            document.getElementById('haBtnSync').disabled = !s.configured;
            haRefreshBadge();
        });
    }

    // Called on-blur of the backup IP: quick client-side hint about which
    // TLS mode the server will default to. Purely cosmetic — the server
    // enforces its own detection.
    function haDetectSameNetwork() {
        var ip = document.getElementById('haRemoteIp').value.trim();
        var hint = document.getElementById('haNetworkHint');
        if (!ip) { hint.textContent = ''; return; }
        // Very rough client-side check: RFC1918 → likely same network.
        var m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (m) {
            var a = +m[1], b = +m[2];
            var rfc1918 = (a === 10) ||
                          (a === 172 && b >= 16 && b <= 31) ||
                          (a === 192 && b === 168);
            if (rfc1918) {
                hint.innerHTML = '<i class="fa fa-check-circle text-success"></i> Looks like a private/LAN address &mdash; TLS verification will default off.';
                var tls = document.getElementById('haVerifyTls');
                if (tls && !tls.dataset.userSet) { tls.checked = false; }
                return;
            }
        }
        hint.innerHTML = '<i class="fa fa-globe text-warning"></i> Looks like a public/remote address &mdash; TLS verification will default on.';
        var tls = document.getElementById('haVerifyTls');
        if (tls && !tls.dataset.userSet) { tls.checked = true; }
    }

    function haFormBody(extra) {
        var body = new URLSearchParams();
        body.append('__csrf_magic',       getCsrf());
        body.append('ha_enabled',         document.getElementById('haEnabled').checked ? 'true' : 'false');
        body.append('ha_remote_ip',       document.getElementById('haRemoteIp').value.trim());
        body.append('ha_remote_port',     document.getElementById('haRemotePort').value.trim() || '443');
        body.append('ha_remote_user',     document.getElementById('haRemoteUser').value.trim() || 'admin');
        body.append('ha_remote_pass',     document.getElementById('haRemotePass').value);
        body.append('ha_verify_tls',      document.getElementById('haVerifyTls').checked ? 'true' : 'false');
        body.append('ha_sync_wg_package',   document.getElementById('haSyncWgPackage').checked   ? 'true' : 'false');
        body.append('ha_sync_wgx_settings', document.getElementById('haSyncWgxSettings').checked ? 'true' : 'false');
        body.append('ha_sync_fw_rules',     document.getElementById('haSyncFwRules').checked     ? 'true' : 'false');
        body.append('ha_auto_sync',         document.getElementById('haAutoSync').checked         ? 'true' : 'false');
        if (extra) { for (var k in extra) { body.append(k, extra[k]); } }
        return body;
    }

    function haRenderSteps(title, resp) {
        var panel = document.getElementById('haStepsPanel');
        var listE = document.getElementById('haStepsList');
        var titlE = document.getElementById('haStepsTitle');
        panel.style.display = '';
        titlE.innerHTML = '<i class="fa fa-stethoscope"></i> ' + title;
        listE.innerHTML  = '';
        (resp.steps || []).forEach(function(st) {
            var icon = st.ok ? '<i class="fa fa-check-circle text-success"></i>'
                             : '<i class="fa fa-times-circle text-danger"></i>';
            var cls  = st.ok ? 'list-group-item-success' : 'list-group-item-danger';
            var li   = document.createElement('li');
            li.className = 'list-group-item ' + cls;
            li.style.fontSize = '13px';
            li.innerHTML = icon + ' <strong>' + haEscape(st.label) + '</strong>' +
                           '<div style="margin-left:22px; font-size:12px;">' + haEscape(st.msg || '') + '</div>';
            listE.appendChild(li);
        });
        panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function haEscape(s) {
        return String(s).replace(/[&<>"']/g, function(c) {
            return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
        });
    }

    function haTestConnection() {
        var btn = document.getElementById('haBtnTest');
        var orig = btn.innerHTML;
        btn.disabled = true; btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Testing…';
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: haFormBody({ action: 'ha_test' })
        }).then(function(r) { return r.json(); })
          .then(function(resp) {
            haRenderSteps(resp.success ? 'Connection OK' : 'Connection failed', resp);
            if (resp.source_ip) {
                var hint = document.getElementById('haNetworkHint');
                hint.innerHTML = '<i class="fa fa-info-circle"></i> ' +
                                 (resp.same_network ? 'Same network detected' : 'Remote/WAN detected') +
                                 ' &mdash; this box would connect from <code>' + haEscape(resp.source_ip) + '</code>';
            }
          }).catch(function(e) {
            haRenderSteps('Connection failed', { steps: [{ label: 'Network', ok: false, msg: String(e) }] });
          }).finally(function() {
            btn.disabled = false; btn.innerHTML = orig;
          });
    }

    function haSaveSettings() {
        var btn = document.getElementById('haBtnSave');
        var orig = btn.innerHTML;
        btn.disabled = true; btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Saving…';
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: haFormBody({ action: 'ha_save' })
        }).then(function(r) { return r.json(); })
          .then(function(resp) {
            if (resp.success) {
                document.getElementById('haRemotePass').value = '';   // clear from DOM
                document.getElementById('haBtnSync').disabled = false;
                haRenderSteps('Saved', { steps: [{ label: 'Settings', ok: true,
                    msg: resp.message + (resp.same_network ? ' (same-network mode)' : ' (remote mode)') }] });
                haRefreshBadge();
            } else {
                haRenderSteps('Save failed', { steps: [{ label: 'Settings', ok: false, msg: resp.message || 'unknown error' }] });
            }
          }).catch(function(e) {
            haRenderSteps('Save failed', { steps: [{ label: 'Network', ok: false, msg: String(e) }] });
          }).finally(function() {
            btn.disabled = false; btn.innerHTML = orig;
          });
    }

    // Collapse/expand the bootstrap panel with a chevron flip.
    function haBootstrapToggle() {
        var body = document.getElementById('haBootstrapBody');
        var chev = document.getElementById('haBootstrapChevron');
        if (!body) return;
        var open = body.style.display === 'none' || body.style.display === '';
        // We toggle: if currently hidden ("none" or ""), show; else hide.
        if (body.style.display === 'none') {
            body.style.display = '';
            if (chev) { chev.classList.remove('fa-chevron-down'); chev.classList.add('fa-chevron-up'); }
        } else {
            body.style.display = 'none';
            if (chev) { chev.classList.remove('fa-chevron-up'); chev.classList.add('fa-chevron-down'); }
        }
    }

    // Add the bootstrap WAN allow-rule on the LOCAL box for the given
    // primary IP. Runs on the backup, per the panel's instructions.
    function haBootstrapAllow() {
        var ipEl   = document.getElementById('haBootstrapIp');
        var portEl = document.getElementById('haBootstrapPort');
        var btn    = document.getElementById('haBootstrapBtn');
        var ip     = (ipEl.value || '').trim();
        if (!ip) {
            haRenderSteps('Bootstrap allow rule', { steps: [{
                label: 'Primary IP', ok: false,
                msg: 'Enter the IP the primary will connect FROM (its WAN if remote, its LAN if same network).'
            }] });
            ipEl.focus();
            return;
        }
        var body = new URLSearchParams();
        body.append('action', 'ha_bootstrap_allow');
        body.append('__csrf_magic', getCsrf());
        body.append('primary_ip', ip);
        if (portEl.value.trim()) { body.append('port', portEl.value.trim()); }

        var orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Installing rule…';
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        }).then(function(r) { return r.json(); })
          .then(function(resp) {
            haRenderSteps(resp.success ? 'Bootstrap allow rule added' : 'Bootstrap failed', resp);
          }).catch(function(e) {
            haRenderSteps('Bootstrap failed', { steps: [{ label: 'Network', ok: false, msg: String(e) }] });
          }).finally(function() {
            btn.disabled = false;
            btn.innerHTML = orig;
          });
    }

    function haSyncNow() {
        var btn = document.getElementById('haBtnSync');
        var orig = btn.innerHTML;
        btn.disabled = true; btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Syncing…';
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=ha_sync_now&__csrf_magic=' + encodeURIComponent(getCsrf())
        }).then(function(r) { return r.json(); })
          .then(function(resp) {
            haRenderSteps(resp.success ? 'Sync complete' : 'Sync failed', resp);
            haRefreshBadge();
          }).catch(function(e) {
            haRenderSteps('Sync failed', { steps: [{ label: 'Network', ok: false, msg: String(e) }] });
          }).finally(function() {
            btn.disabled = false; btn.innerHTML = orig;
          });
    }

    // Small badge on the toolbar HA Sync button — green when configured &
    // last sync ok, yellow when never synced, red when last sync failed.
    function haRefreshBadge() {
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'action=ha_status&__csrf_magic=' + encodeURIComponent(getCsrf())
        }).then(function(r) { return r.json(); })
          .then(function(s) {
            var badge = document.getElementById('haSyncBadge');
            if (!badge) return;
            if (!s.enabled || !s.configured) { badge.style.display = 'none'; return; }
            if (s.last_status === 'success') {
                badge.style.background = '#4caf50'; badge.style.color = '#fff';
                badge.textContent = 'OK';
            } else if (s.last_status === 'failed') {
                badge.style.background = '#e57373'; badge.style.color = '#fff';
                badge.textContent = '!';
            } else {
                badge.style.background = '#ffb74d'; badge.style.color = '#000';
                badge.textContent = '?';
            }
            badge.style.display = 'inline-block';
          }).catch(function() {});
    }
    // Kick off a badge refresh on load. If HA isn't configured this is a
    // single cheap POST and the badge stays hidden.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', haRefreshBadge);
    } else {
        haRefreshBadge();
    }


    // Download a GET endpoint via fetch so the CSRF token travels in a
    // request header instead of the URL (keeps it out of webserver logs).
    function wgxDownload(url, fallbackName) {
        return fetch(url, { headers: { 'X-WGX-CSRF': getCsrf() } })
            .then(function(r) {
                if (!r.ok) { throw new Error('Download failed (HTTP ' + r.status + ')'); }
                var cd = r.headers.get('Content-Disposition') || '';
                var m = cd.match(/filename="?([^";]+)"?/i);
                var name = m ? m[1] : (fallbackName || 'download.bin');
                return r.blob().then(function(b) { return { blob: b, name: name }; });
            })
            .then(function(d) {
                var a = document.createElement('a');
                a.href = URL.createObjectURL(d.blob);
                a.download = d.name;
                document.body.appendChild(a);
                a.click();
                setTimeout(function() { URL.revokeObjectURL(a.href); a.remove(); }, 4000);
            })
            .catch(function(e) { alert(e.message || 'Download failed'); });
    }

    document.getElementById('selectAll').addEventListener('change', function() {
        document.querySelectorAll('.peer-checkbox').forEach(c => c.checked = this.checked);
        updateBulkToolbar();
    });

    document.getElementById('peersTable').addEventListener('change', function(e) {
        if (e.target.classList.contains('peer-checkbox')) updateBulkToolbar();
    });

    function updateBulkToolbar() {
        const checked = document.querySelectorAll('.peer-checkbox:checked');
        const toolbar = document.getElementById('bulkToolbar');
        const count = document.getElementById('bulkCount');
        toolbar.style.display = checked.length > 0 ? '' : 'none';
        count.textContent = checked.length + ' peer' + (checked.length !== 1 ? 's' : '') + ' selected';
    }

    function openBulkExtendModal() {
        const sel = [...document.querySelectorAll('.peer-checkbox:checked')].map(c => c.value);
        if (!sel.length) { alert('Select at least one peer.'); return; }
        $('#bulkExtendModal').modal('show');
    }

    function confirmBulkExtend() {
        const days = parseInt(document.getElementById('bulkExtendDays').value) || 30;
        const sel = [...document.querySelectorAll('.peer-checkbox:checked')].map(c => c.value);
        $('#bulkExtendModal').modal('hide');
        const body = new URLSearchParams({
            action: 'bulk_action',
            sub_action: 'extend_expiry',
            indices: sel.join(','),
                                         extend_days: days,
                                         __csrf_magic: getCsrf()
        });
        fetch('/wgx/vpn_wg_export.php', { method: 'POST', body })
        .then(r => r.json())
        .then(data => {
            if (data.success) { location.reload(); }
            else { alert('Error: ' + (data.message || 'Unknown error')); }
        })
        .catch(e => alert('Request failed: ' + e.message));
    }

    function bulkAction(sub) {
        const sel = [...document.querySelectorAll('.peer-checkbox:checked')].map(c => c.value);
        if (!sel.length) {
            alert('Select at least one peer.');
            return;
        }
        const labels = {
            delete: 'permanently delete',
            disable: 'disable',
            enable: 'enable',
            rotate_keys: 'rotate keys for'
        };
        if (!confirm(`Are you sure you want to ${labels[sub]} ${sel.length} peer(s)?`)) return;
        const body = new URLSearchParams({
            action: 'bulk_action',
            sub_action: sub,
            indices: sel.join(','),
            __csrf_magic: getCsrf()
        });
        fetch('/wgx/vpn_wg_export.php', {
                method: 'POST',
                body: body
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(e => alert('Request failed: ' + e.message));
    }
    // Show/hide date range fields when schedule type changes
    (function() {
        const schedSel = document.getElementById('peerSchedule');
        if (schedSel) {
            schedSel.addEventListener('change', function() {
                const wrap = document.getElementById('dateRangeWrap');
                if (wrap) wrap.style.display = this.value === 'date_range' ? '' : 'none';
            });
        }
    })();

    document.getElementById('searchPeers').addEventListener('input', function() {
        sessionStorage.setItem('wgx_peer_search', this.value);
        applyFilters();
    });

    // Restore last search on page load
    (function() {
        const saved = sessionStorage.getItem('wgx_peer_search');
        if (saved) {
            const el = document.getElementById('searchPeers');
            if (el) { el.value = saved; applyFilters(); }
        }
    })();

    function downloadSelected() {
        const sel = [...document.querySelectorAll('.peer-checkbox:checked')].map(c => c.value);
        if (!sel.length) {
            alert("Select at least one peer.");
            return;
        }
        wgxDownload(`/wgx/vpn_wg_export.php?action=bulk_export&selected_peers=${encodeURIComponent(sel.join(','))}`, 'wgx_peers_export.zip');
    }

    function downloadAll() {
        wgxDownload('/wgx/vpn_wg_export.php?action=bulk_export', 'wgx_peers_export.zip');
    }

    function openGlobalSettings() {
        $('#globalSettingsModal').modal('show');
    }

    function testWebhook() {
        const url = document.getElementById('webhookUrl') ? document.getElementById('webhookUrl').value.trim() : '';
        if (!url) { alert('Enter a webhook URL first.'); return; }
        const status = document.getElementById('webhookTestStatus');
        status.textContent = 'Sending…';
        const body = new URLSearchParams({
            action: 'test_webhook',
            __csrf_magic: getCsrf()
        });
        fetch('/wgx/vpn_wg_export.php', { method: 'POST', body })
        .then(r => r.json())
        .then(data => {
            status.textContent = data.success ? '✓ Sent successfully' : '✗ ' + (data.message || 'Failed');
            status.style.color = data.success ? 'green' : 'red';
        })
        .catch(() => { status.textContent = '✗ Request failed'; status.style.color = 'red'; });
    }

    function saveGlobalSettings() {
        const body = new URLSearchParams();
        body.append('action', 'save_global');
        body.append('__csrf_magic', getCsrf());
        body.append('enforce_psk', document.getElementById('setEnforcePsk') && document.getElementById('setEnforcePsk').checked ? 'true' : 'false');
        if (document.getElementById('fallbackSubnets')) body.append('fallback_subnets', document.getElementById('fallbackSubnets').value);

        // --- POST NEW VARIABLES ---
        if (document.getElementById('defaultDns')) body.append('default_dns', document.getElementById('defaultDns').value);
        if (document.getElementById('defaultKa')) body.append('default_ka', document.getElementById('defaultKa').value);
        if (document.getElementById('defaultTier')) body.append('default_tier', document.getElementById('defaultTier').value);
        if (document.getElementById('keyRotationDays')) body.append('key_rotation_days', document.getElementById('keyRotationDays').value);
        body.append('auto_cron', document.getElementById('autoCronEnable') && document.getElementById('autoCronEnable').checked ? 'true' : 'false');
        body.append('enable_geo', document.getElementById('enableGeo') && document.getElementById('enableGeo').checked ? 'true' : 'false');
        // Webhook
        if (document.getElementById('webhookUrl')) body.append('webhook_url', document.getElementById('webhookUrl').value.trim());
        ['expiry','rotation','quota','peer_add'].forEach(function(ev) {
            const el = document.getElementById('webhookEvent_' + ev);
            if (el && el.checked) body.append('webhook_event_' + ev, '1');
        });
            // Per-tunnel peer limits
        document.querySelectorAll('.tunnel-peer-limit').forEach(function(inp) {
            body.append('peer_limit_' + inp.dataset.tun, inp.value || '0');
        });

        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(async r => r.json()).then(data => {
            alert(data.message);
            if (data.success) location.reload();
        });
    }

    function openCsvModal() {
        $('#csvModal').modal('show');
    }

    function processCsv() {
        const data = document.getElementById('csvDataInput').value.trim();
        const tun = document.getElementById('csvTunnelSelect').value;
        if (!data) {
            alert("Please enter CSV data.");
            return;
        }
        const body = new URLSearchParams({
            action: 'bulk_csv',
            __csrf_magic: getCsrf(),
            csv_data: data,
            tun: tun
        });
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(async r => r.json()).then(resp => {
            alert(resp.message);
            if (resp.success) {
                location.reload();
            }
        }).catch(e => alert("Error processing CSV."));
    }

    function handleCsvUpload(e) {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = function(evt) {
            // Drop the file contents straight into the textarea
            document.getElementById('csvDataInput').value = evt.target.result;
        };
        reader.readAsText(file);

        // Reset the input so you can select the same file again if you clear it
        e.target.value = '';
    }

    function openRestoreModal() {
        $('#restoreModal').modal('show');
    }

    function processRestore() {
        const tun = document.getElementById('restoreTunnelSelect').value;
        const fileInput = document.getElementById('restoreFileInput');

        if (!fileInput.files.length) {
            alert("Please select a .tar.gz backup file.");
            return;
        }

        const formData = new FormData();
        formData.append('action', 'restore_tar');
        formData.append('__csrf_magic', getCsrf());
        formData.append('tun', tun);
        formData.append('backup_file', fileInput.files[0]);

        const btn = document.querySelector('#restoreModal .btn-primary');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Restoring...';
        btn.disabled = true;

        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: formData
        }).then(async r => r.json()).then(resp => {
            alert(resp.message);
            if (resp.success) {
                location.reload();
            }
        }).catch(e => {
            alert("Error processing the restore file.");
        }).finally(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
        });
    }

    function setClientAllowedIPs(val) {
        document.getElementById('clientAllowedIPs').value = val;
        updateDisplays();
    }

    function setSplitTunnel() {
        setClientAllowedIPs(dynamicSplit);
    }

    function toggleZeroTrustTarget() {
        const tier = document.getElementById('peerTier').value;
        document.getElementById('zeroTrustTargetWrap').style.display = (tier === 'vendor') ? 'block' : 'none';
    }

    function setUIState(mode) {
        modalMode = mode;
        exportFormat = 'client';
        if (typeof setExportFormat === 'function') {
            setExportFormat('client');
        }

        ['clientPrivKey', 'endpointOverride', 'clientPsk', 'clientPubKey', 'peerDescription', 'peerAssignedIP', 'peerExpiryDate', 'peerNotes', 'peerEmail', 'peerGroup', 'peerOfflineAlert'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        if (document.getElementById('peerExpiryPreset')) {
            document.getElementById('peerExpiryPreset').value = '0';
            wgxUpdateExpiry('0');
        }
        if (document.getElementById('peerQuotaPreset')) {
            document.getElementById('peerQuotaPreset').value = 'exempt';
            wgxUpdateQuota('exempt');
        }
        if (document.getElementById('peerSchedule')) document.getElementById('peerSchedule').value = 'always';
        if (document.getElementById('peerAutoRotate')) document.getElementById('peerAutoRotate').value = '0';
        if (document.getElementById('clientAllowedIPs')) document.getElementById('clientAllowedIPs').value = '0.0.0.0/0, ::/0';

        // --- INJECT GLOBAL SETTINGS INTO UI ---
        if (document.getElementById('peerDNS')) document.getElementById('peerDNS').value = '<?= htmlspecialchars(
                                                                                                $wgx_settings["default_dns"] ?? "8.8.8.8, 8.8.4.4",
                                                                                                ENT_QUOTES
                                                                                            ) ?>';
        if (document.getElementById('peerKeepAlive')) document.getElementById('peerKeepAlive').value = mode === 'add' ? '<?= htmlspecialchars(
                                                                                                                                $wgx_settings["default_ka"] ?? "25",
                                                                                                                                ENT_QUOTES
                                                                                                                            ) ?>' : '';
        if (document.getElementById('peerTier') && mode === 'add') {
            document.getElementById('peerTier').value = '<?= htmlspecialchars(
                                                                $wgx_settings["default_tier"] ?? "admin",
                                                                ENT_QUOTES
                                                            ) ?>';
            toggleZeroTrustTarget();
        }
        // --------------------------------------

        if (document.getElementById('confText')) document.getElementById('confText').value = 'Loading…';
        if (document.getElementById('qrcode_canvas')) document.getElementById('qrcode_canvas').innerHTML = '';

        ['rowAddNewParams', 'rowKeyParams', 'rowRouteParams', 'rowDnsParams'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = '';
        });

        if (mode === 'export') {
            ['btnWrapAddPeer', 'btnWrapGenKeys'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            });
            ['btnWrapGenPsk', 'pskCheckboxWrapper'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            });
            ['clientPrivKey', 'clientPsk'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.readOnly = false;
            });
            ['tunnelSelect', 'peerDescription', 'peerTier', 'peerTarget', 'peerAssignedIP', 'peerExpiryDate', 'peerSchedule', 'peerAutoRotate'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.disabled = false;
            });
            if (document.getElementById('btnWrapDownload')) document.getElementById('btnWrapDownload').className = 'col-sm-12';
            if (document.getElementById('exportFmtToggle')) document.getElementById('exportFmtToggle').style.display = 'inline-block';
        } else {
            ['rowAddNewParams', 'btnWrapAddPeer', 'btnWrapGenKeys', 'btnWrapGenPsk', 'pskCheckboxWrapper'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            });
            ['clientPrivKey', 'clientPsk'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.readOnly = true;
            });
            ['tunnelSelect', 'peerDescription', 'peerTier', 'peerTarget', 'peerAssignedIP', 'peerExpiryDate', 'peerSchedule'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.disabled = false;
            });
            if (document.getElementById('pskEnabled')) document.getElementById('pskEnabled').checked = false;
            if (document.getElementById('refreshPskBtn')) document.getElementById('refreshPskBtn').disabled = true;
            if (document.getElementById('btnWrapDownload')) document.getElementById('btnWrapDownload').className = 'col-sm-6';
            if (document.getElementById('exportFmtToggle')) document.getElementById('exportFmtToggle').style.display = 'none';
        }
    }

    function parseImportedConf(text) {
        if (!text) return;
        let privMatch = text.match(/PrivateKey\s*=\s*([A-Za-z0-9+\/]{43}=)/i);
        let pubMatch = text.match(/PublicKey\s*=\s*([A-Za-z0-9+\/]{43}=)/i);
        let ipMatch = text.match(/Address\s*=\s*([0-9a-fA-F\.\:\/, ]+)/i) || text.match(/AllowedIPs\s*=\s*([0-9a-fA-F\.\:\/, ]+)/i);
        let descMatch = text.match(/#\s*(.+)/);

        if (ipMatch) {
            document.getElementById('peerAssignedIP').value = ipMatch[1].split(',')[0].trim();
        }
        if (descMatch && descMatch[1].trim() !== '') {
            document.getElementById('peerDescription').value = descMatch[1].trim();
        }

        if (privMatch) {
            document.getElementById('clientPrivKey').value = privMatch[1];
            fetch('/wgx/vpn_wg_export.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: `action=derive_pub&__csrf_magic=${encodeURIComponent(getCsrf())}&privkey=${encodeURIComponent(privMatch[1])}`
                })
                .then(r => r.json())
                .then(d => {
                    if (d.success && d.pub) {
                        document.getElementById('clientPubKey').value = d.pub;
                        updateDisplays();
                    }
                });
        } else if (pubMatch) {
            document.getElementById('clientPubKey').value = pubMatch[1];
            updateDisplays();
        } else {
            updateDisplays();
        }
    }

    function handleConfUpload(e) {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = function(evt) {
            openAddPeerModal();
            document.getElementById('peerDescription').value = file.name.replace(/\.[^/.]+$/, "").replace(/[^a-zA-Z0-9 -]/g, '');
            parseImportedConf(evt.target.result);
        };
        reader.readAsText(file);
        e.target.value = '';
    }

    function deletePeer(idx, name) {
        if (!confirm(`Are you sure you want to PERMANENTLY delete the peer "${name}"? This action cannot be undone.`)) {
            return;
        }
        const body = new URLSearchParams({
            action: 'delete_peer',
            __csrf_magic: getCsrf(),
            idx: idx
        });
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(r => r.json()).then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to delete peer: ' + data.message);
            }
        });
    }

    function wgxDeleteTunnel(tn, peerCount) {
        let cascade = '0';
        if (peerCount > 0) {
            const plural = peerCount === 1 ? '' : 's';
            if (!confirm(`Tunnel "${tn}" still has ${peerCount} peer${plural}.\n\nOK = delete the tunnel AND its ${peerCount} peer${plural} (kernel + config)\nCancel = abort`)) {
                return;
            }
            cascade = '1';
        }
        const typed = prompt(`This will PERMANENTLY delete tunnel "${tn}"${cascade === '1' ? ' and all of its peers' : ''}, remove the interface from the kernel, and clean up its WGX-managed outbound NAT rule. This cannot be undone.\n\nType the tunnel name to confirm:`);
        if (typed === null) { return; }
        if (typed.trim() !== tn) {
            alert('Name mismatch — deletion aborted.');
            return;
        }
        const body = new URLSearchParams({
            action: 'delete_tunnel',
            __csrf_magic: getCsrf(),
            tun_name: tn,
            confirm_name: typed.trim(),
            cascade_peers: cascade
        });
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(r => r.json()).then(data => {
            if (data.success) {
                location.reload();
            } else if (data.needs_cascade) {
                alert(data.message);
            } else {
                alert('Failed to delete tunnel: ' + data.message);
            }
        }).catch(e => {
            alert('Failed to delete tunnel: ' + e);
        });
    }

    let doctorPeerIdx = -1;
    function wgxOpenDoctor(idx, name) {
        doctorPeerIdx = idx;
        document.getElementById('doctorPeerName').textContent = name;
        wgxRunDoctor();
        $('#doctorModal').modal('show');
    }
    function wgxRunDoctor() {
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
        const spin = document.getElementById('doctorSpinner');
        const res  = document.getElementById('doctorResults');
        spin.style.display = '';
        res.style.display = 'none';
        fetch('/wgx/vpn_wg_export.php?action=peer_doctor&peer_idx=' + encodeURIComponent(doctorPeerIdx) + '&_t=' + Date.now(), {
            headers: { 'X-WGX-CSRF': getCsrf() }
        }).then(r => r.json()).then(data => {
            spin.style.display = 'none';
            res.style.display = '';
            const box = document.getElementById('doctorChecks');
            if (!data.success) {
                box.innerHTML = '<div class="alert alert-danger" style="margin:0;">' + esc(data.message || 'Doctor run failed.') + '</div>';
                document.getElementById('doctorNext').style.display = 'none';
                return;
            }
            const meta = {
                pass: ['fa-check-circle',        '#27ae60', 'PASS'],
                warn: ['fa-exclamation-triangle', '#f39c12', 'WARN'],
                fail: ['fa-times-circle',         '#c0392b', 'FAIL'],
                info: ['fa-info-circle',          '#2980b9', 'INFO'],
                skip: ['fa-minus-circle',         '#95a5a6', 'SKIP']
            };
            box.innerHTML = (data.checks || []).map(c => {
                const m = meta[c.status] || meta.info;
                const fix = (c.fix && (c.status === 'fail' || c.status === 'warn'))
                    ? `<div style="margin-top:3px; font-size:11px;"><i class="fa fa-wrench"></i> <em>${esc(c.fix)}</em></div>`
                    : '';
                return `<div style="padding:7px 4px; border-bottom:1px solid rgba(128,128,128,0.15);">
                    <div>
                        <i class="fa ${m[0]}" style="color:${m[1]}; width:18px;"></i>
                        <strong style="font-size:12px;">${esc(c.title)}</strong>
                        <span style="float:right; font-size:10px; font-weight:700; color:${m[1]};">${m[2]}</span>
                    </div>
                    <div style="font-size:12px; margin-left:24px; opacity:0.9;">${esc(c.detail)}${fix}</div>
                </div>`;
            }).join('');
            const s = data.summary || {};
            const nextEl = document.getElementById('doctorNext');
            nextEl.style.display = '';
            nextEl.className = 'alert ' + ((s.fail || 0) > 0 ? 'alert-danger' : ((s.warn || 0) > 0 ? 'alert-warning' : 'alert-success'));
            nextEl.innerHTML = '<strong>' + ((s.fail || 0) > 0 ? 'Next step:' : ((s.warn || 0) > 0 ? 'Suggestion:' : 'Healthy:')) + '</strong> ' + esc(data.next_action || '');
        }).catch(e => {
            spin.style.display = 'none';
            res.style.display = '';
            document.getElementById('doctorChecks').innerHTML = '<div class="alert alert-danger" style="margin:0;">Doctor request failed: ' + String(e) + '</div>';
        });
    }
    document.addEventListener('DOMContentLoaded', function() {
        const rb = document.getElementById('doctorRerun');
        if (rb) { rb.addEventListener('click', wgxRunDoctor); }
    });

    function killPeer(tun, pubkey) {
        if (!confirm("Are you sure you want to kill this connection? This will drop the peer from the kernel and disable it immediately.")) {
            return;
        }
        const body = new URLSearchParams({
            action: 'kill_peer',
            __csrf_magic: getCsrf(),
            tun: tun,
            pubkey: pubkey
        });
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(r => r.json()).then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to kill peer: ' + data.message);
            }
        });
    }

    function rotateKeys(idx, name) {
        if (!confirm(`WARNING: This will immediately revoke current access for "${name}" and generate new keys in the kernel. Proceed?`)) {
            return;
        }
        const body = new URLSearchParams({
            action: 'rotate_keys',
            __csrf_magic: getCsrf(),
            idx: idx
        });
        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body: body
        }).then(r => r.json()).then(data => {
            if (data.success) {
                alert(`Success! New Private Key for ${name}:\n\n${data.new_priv}\n\nYou MUST re-export and provide this to the user.`);
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        });
    }

    function openEmailModal(idx, name, prefillEmail) {
        fetch(`/wgx/vpn_wg_export.php?action=get_conf_data&peer_idx=${encodeURIComponent(idx)}`, {
            method: 'GET', headers: { 'X-WGX-CSRF': getCsrf() }
        }).then(async r => r.json()).then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            document.getElementById('emailPeerName').value = name;
            document.getElementById('emailPeerIdx').value = idx;
            document.getElementById('emailModalLabel').textContent = 'Email Config: ' + name;

            // Pre-fill email from peer profile if available
            var emailField = document.getElementById('emailTarget');
            var prefillNote = document.getElementById('emailPrefillNote');
            var storedEmail = prefillEmail || data.peer_email || '';
            emailField.value = storedEmail;
            if (prefillNote) prefillNote.style.display = storedEmail ? '' : 'none';

            // Show/hide WS bundle notice
            var wsNotice = document.getElementById('emailWsNotice');
            var isWs = data.ws_transport && data.ws_server_ip;
            document.getElementById('emailIsWs').value = isWs ? '1' : '0';
            if (wsNotice) wsNotice.style.display = isWs ? '' : 'none';

            // For WS peers hide the email field and send button — attachments not supported
            var emailFieldRow = document.getElementById('emailTarget') ? document.getElementById('emailTarget').closest('.form-group') : null;
            var smtpNotice = document.getElementById('emailSmtpNotice');
            var sendBtn = document.getElementById('btnSendMail');
            var dlConfBtn = document.getElementById('btnDownloadConf');
            if (isWs) {
                if (emailFieldRow) emailFieldRow.style.display = 'none';
                if (smtpNotice) smtpNotice.style.display = 'none';
                if (sendBtn) sendBtn.style.display = 'none';
                if (dlConfBtn) {
                    dlConfBtn.style.display = '';
                    dlConfBtn.innerHTML = '<i class="fa fa-download"></i> Download Bundle to Email Manually';
                }
            } else {
                if (emailFieldRow) emailFieldRow.style.display = '';
                if (smtpNotice) smtpNotice.style.display = '';
                if (dlConfBtn) {
                    dlConfBtn.style.display = '';
                    dlConfBtn.innerHTML = '<i class="fa fa-download"></i> Download .conf to Email Manually';
                }
                if (sendBtn) {
                    sendBtn.style.display = '';
                    sendBtn.innerHTML = '<i class="fa fa-paper-plane"></i> Send via pfSense SMTP';
                }
            }

            let conf = data.template;
            let priv = data.existing_privkey ? data.existing_privkey : '<ENTER_PRIVATE_KEY_HERE_IF_KNOWN>';
            conf = conf.replace('__PRIVATE_KEY_PLACEHOLDER__', priv);
            conf = conf.replace(/__ENDPOINT_PLACEHOLDER__|^Endpoint = .*/m, 'Endpoint = ' + data.default_endpoint);
            conf = conf.replace(/__ALLOWEDIPS_PLACEHOLDER__|^AllowedIPs = .*/m, 'AllowedIPs = 0.0.0.0/0, ::/0');
            conf = conf.replace('__DNS_PLACEHOLDER__', 'DNS = 8.8.8.8, 8.8.4.4');
            if (data.existing_keepalive) {
                conf = conf.replace(/__KEEPALIVE_PLACEHOLDER__|^PersistentKeepalive = .*/m, 'PersistentKeepalive = ' + data.existing_keepalive);
            } else {
                conf = conf.replace(/__KEEPALIVE_PLACEHOLDER__|^PersistentKeepalive = .*/m, 'PersistentKeepalive = 25');
            }
            if (data.existing_psk) {
                conf = conf.replace('__PSK_PLACEHOLDER__', 'PresharedKey = ' + data.existing_psk);
            } else {
                conf = conf.replace(/^__PSK_PLACEHOLDER__\n?/m, '');
            }
            document.getElementById('emailConfData').value = conf;
            $('#emailModal').modal('show');
        }).catch(e => {
            alert("Failed to prepare email configuration.");
        });
    }

    function downloadEmailConf() {
        var name = document.getElementById('emailPeerName').value;
        var conf = document.getElementById('emailConfData').value;
        if (!conf) {
            alert('No configuration available.');
            return;
        }
        var safeName = (name || 'peer').replace(/[^a-zA-Z0-9_-]/g, '_');
        var blob = new Blob([conf], {
            type: 'text/plain'
        });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = safeName + '.conf';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    }

    function sendEmailReq() {
        const to = document.getElementById('emailTarget').value.trim();
        if (!to) {
            alert('Enter an email address.');
            return;
        }
        const btn = document.getElementById('btnSendMail');
        btn.disabled = true;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Sending...';

        const body = new URLSearchParams();
        body.append('action', 'email_peer');
        body.append('__csrf_magic', getCsrf());
        body.append('email', to);
        body.append('conf', document.getElementById('emailConfData').value);
        body.append('name', document.getElementById('emailPeerName').value);
        fetch('/wgx/vpn_wg_export.php', {
                method: 'POST',
                body: body
            })
            .then(async r => r.json())
            .then(data => {
                alert(data.message);
                if (data.success) {
                    $('#emailModal').modal('hide');
                }
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa fa-paper-plane"></i> Send Configuration';
            });
    }

    function openExportModal(peerIdx, peerName) {
        currentPeerName = peerName;
        setUIState('export');
        document.getElementById('exportModalLabel').textContent = 'Export: ' + peerName;

        populateTunnelSelect();

        fetch(`/wgx/vpn_wg_export.php?action=get_conf_data&peer_idx=${encodeURIComponent(peerIdx)}&_t=${Date.now()}`, { headers: { 'X-WGX-CSRF': getCsrf() } }).then(async r => {
            if (!r.ok) throw new Error(r.status);
            return r.json();
        }).then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            rawTemplateText = data.template;
            defaultEndpoint = data.default_endpoint;
            document.getElementById('endpointOverride').placeholder = 'Default: ' + defaultEndpoint;

            document.getElementById('clientPubKey').value = data.peer_pubkey || '';
            document.getElementById('peerDescription').value = data.peer_desc || '';
            if (document.getElementById('peerEmail')) document.getElementById('peerEmail').value = data.peer_email || '';
            if (document.getElementById('peerNotes')) document.getElementById('peerNotes').value = data.peer_notes || '';
            if (document.getElementById('peerDNS')) document.getElementById('peerDNS').value = data.peer_dns_override || '';
            if (document.getElementById('schedDateFrom')) document.getElementById('schedDateFrom').value = data.peer_sched_from || '';
            if (document.getElementById('schedDateTo')) document.getElementById('schedDateTo').value = data.peer_sched_to || '';
            if (document.getElementById('peerGroup')) document.getElementById('peerGroup').value = data.peer_group || '';
            if (document.getElementById('peerOfflineAlert')) document.getElementById('peerOfflineAlert').value = data.offline_alert_hours || '0';
            if (document.getElementById('peerSchedule')) {
                document.getElementById('peerSchedule').dispatchEvent(new Event('change'));
            }
            if (document.getElementById('tunnelSelect')) {
                if (data.peer_tun) {
                    document.getElementById('tunnelSelect').value = data.peer_tun;
                } else {
                    document.getElementById('tunnelSelect').selectedIndex = 0;
                }
            }
            if (document.getElementById('peerTier') && data.peer_tier) document.getElementById('peerTier').value = data.peer_tier;
            if (document.getElementById('peerTarget')) document.getElementById('peerTarget').value = data.peer_target || '';
            if (document.getElementById('peerSchedule') && data.peer_schedule) document.getElementById('peerSchedule').value = data.peer_schedule;
            if (document.getElementById('peerAutoRotate') && data.peer_autorotate) document.getElementById('peerAutoRotate').value = data.peer_autorotate;

            let ipMatch = rawTemplateText.match(/Address\s*=\s*([^,\n]+)/i);
            if (ipMatch) {
                document.getElementById('peerAssignedIP').value = ipMatch[1].trim();
            }
            toggleZeroTrustTarget();

            // --- NEW: Sync the PSK Checkbox with the fetched data ---
            if (data.existing_psk) {
                document.getElementById('clientPsk').value = data.existing_psk;
                if (document.getElementById('pskEnabled')) {
                    document.getElementById('pskEnabled').checked = true;
                    if (document.getElementById('refreshPskBtn')) document.getElementById('refreshPskBtn').disabled = false;
                }
            } else {
                if (document.getElementById('pskEnabled')) {
                    document.getElementById('pskEnabled').checked = false;
                    if (document.getElementById('refreshPskBtn')) document.getElementById('refreshPskBtn').disabled = true;
                }
            }
            // --------------------------------------------------------

            if (data.existing_privkey) {
                document.getElementById('clientPrivKey').value = data.existing_privkey;
                setTimeout(() => {
                    alert("SECURITY NOTICE:\n\nThis is your ONE-TIME view of the generated Private Key.\n\nIt has now been permanently deleted from the firewall for your security. Please scan the QR code or download the file now.");
                }, 500);
            }
            document.getElementById('peerKeepAlive').value = data.existing_keepalive || '25';
            updateDisplays();
            updateQrExpiryNotice(data.conf_token_fresh !== false);

            var stdPanel = document.getElementById('standardOutputPanel');
            if (stdPanel) stdPanel.style.display = '';

            $('#exportModal').modal('show');
        }).catch(e => {
            alert("Failed to fetch configuration from pfSense. " + e.message);
        });
    }

    function openAddPeerModal() {
        currentPeerName = 'NewPeer';
        setUIState('add');
        document.getElementById('exportModalLabel').textContent = 'Provision New Peer';
        rawTemplateText = "[Interface]\nPrivateKey = __PRIVATE_KEY_PLACEHOLDER__\nAddress = 10.x.x.x/32\n__DNS_PLACEHOLDER__\nMTU = 1420\n\n[Peer]\nPublicKey = __SERVERPUB__\n__PSK_PLACEHOLDER__\nEndpoint = __ENDPOINT_PLACEHOLDER__\nAllowedIPs = __ALLOWEDIPS_PLACEHOLDER__\nPersistentKeepalive = __KEEPALIVE_PLACEHOLDER__\n";
        defaultEndpoint = "";
        populateTunnelSelect();

        // --- NEW: Enforce PSK Policy ---
        // Reads the hidden Global Settings checkbox to determine the policy
        if (document.getElementById('setEnforcePsk') && document.getElementById('setEnforcePsk').checked) {
            document.getElementById('pskEnabled').checked = true;
            document.getElementById('refreshPskBtn').disabled = false;
        }
        // -------------------------------

        generateNewKeys();
        $('#exportModal').modal('show');
    }

    function populateTunnelSelect() {
        const sel = document.getElementById('tunnelSelect');
        sel.innerHTML = '';
        tunnelsData.forEach(t => {
            const opt = new Option(t.name, t.name);
            opt.dataset.endpoint  = t.endpoint;
            opt.dataset.pubkey    = t.pubkey;
            opt.dataset.subnet    = t.subnet;
            opt.dataset.nextip    = t.next_ip;
            opt.dataset.peerlimit = t.peer_limit || 0;
            opt.dataset.peercount = t.peer_count || 0;
            sel.appendChild(opt);
        });
        if (tunnelsData.length > 0) {
            sel.selectedIndex = 0;
            document.getElementById('endpointOverride').placeholder = 'Default: ' + (tunnelsData[0].endpoint || tunnelsData[0].name);
            updateTunnelPubKey(tunnelsData[0].pubkey || '');
            document.getElementById('peerAssignedIP').value = tunnelsData[0].next_ip || '';
        }
    }

    function onTunnelChange() {
        const sel = document.getElementById('tunnelSelect');
        const opt = sel.options[sel.selectedIndex];
        document.getElementById('endpointOverride').placeholder = 'Default: ' + (opt.dataset.endpoint || sel.value);
        document.getElementById('endpointOverride').value = '';
        updateTunnelPubKey(opt.dataset.pubkey || '');
        if (modalMode === 'add') {
            document.getElementById('peerAssignedIP').value = opt.dataset.nextip || '';
        }

        // Peer limit indicator
        let limitWarn = document.getElementById('tunnelPeerLimitWarn');
        if (!limitWarn) {
            limitWarn = document.createElement('div');
            limitWarn.id = 'tunnelPeerLimitWarn';
            limitWarn.style.marginTop = '6px';
            document.getElementById('tunnelSelect').parentNode.appendChild(limitWarn);
        }
        const limit = parseInt(opt.dataset.peerlimit) || 0;
        const count = parseInt(opt.dataset.peercount) || 0;
        if (limit > 0) {
            const remaining = limit - count;
            const cls = remaining <= 0 ? 'alert-danger' : remaining <= 2 ? 'alert-warning' : 'alert-info';
            const msg = remaining <= 0
            ? `<i class="fa fa-ban"></i> Peer limit reached (${count}/${limit}) — disable or delete a peer first.`
            : `<i class="fa fa-info-circle"></i> ${count} of ${limit} peer slots used (${remaining} remaining).`;
            limitWarn.innerHTML = `<div class="alert ${cls}" style="padding:6px 10px; margin-bottom:0; font-size:12px;">${msg}</div>`;
            limitWarn.style.display = '';
        } else {
            limitWarn.style.display = 'none';
        }

        updateDisplays();
    }

    function updateTunnelPubKey(pubkey) {
        rawTemplateText = rawTemplateText.replace(/PublicKey = .*/, 'PublicKey = ' + pubkey);
    }

    function updateDisplays() {
        const privKey = document.getElementById('clientPrivKey').value.trim() || '<PASTE_PRIVATE_KEY_HERE>';
        const psk = document.getElementById('clientPsk').value.trim();
        let ep = document.getElementById('endpointOverride').value.trim();
        if (!ep && modalMode === 'add') {
            const _sel = document.getElementById('tunnelSelect');
            const _opt = _sel.options[_sel.selectedIndex];
            ep = (_opt && _opt.dataset.endpoint) ? _opt.dataset.endpoint : '';
        }
        if (!ep) {
            ep = defaultEndpoint;
        }
        let allowedIPs = document.getElementById('clientAllowedIPs') ? document.getElementById('clientAllowedIPs').value.trim() : '0.0.0.0/0, ::/0';
        if (!allowedIPs) {
            allowedIPs = '0.0.0.0/0, ::/0';
        }
        const dns = document.getElementById('peerDNS').value.trim();
        let ka = document.getElementById('peerKeepAlive') ? document.getElementById('peerKeepAlive').value.trim() : '25';
        if (!ka) {
            ka = '25';
        }
        let assignedIP = '10.x.x.x';

        let serverPubMatch = rawTemplateText.match(/PublicKey\s*=\s*(.+)/);
        let serverPub = serverPubMatch ? serverPubMatch[1] : '<SERVER_PUBLIC_KEY>';

        if (modalMode === 'add') {
            const raw_ip = document.getElementById('peerAssignedIP').value.trim() || '10.x.x.x/32';
            assignedIP = raw_ip.split(',')[0].trim();
        } else {
            let ipMatch = rawTemplateText.match(/Address\s*=\s*([^,\n]+)/i);
            if (ipMatch) {
                assignedIP = ipMatch[1].trim();
            }
        }

        let conf = rawTemplateText;
        conf = conf.replace('__PRIVATE_KEY_PLACEHOLDER__', privKey);
        if (psk) {
            conf = conf.replace('__PSK_PLACEHOLDER__', 'PresharedKey = ' + psk);
        } else {
            conf = conf.replace(/^__PSK_PLACEHOLDER__\n?/m, '');
        }
        conf = conf.replace(/__ENDPOINT_PLACEHOLDER__|^Endpoint = .*/m, 'Endpoint = ' + ep);
        conf = conf.replace(/__ALLOWEDIPS_PLACEHOLDER__|^AllowedIPs = .*/m, 'AllowedIPs = ' + allowedIPs);
        if (modalMode === 'add') {
            conf = conf.replace(/^Address = .*/m, 'Address = ' + assignedIP);
        }
        if (dns) {
            conf = conf.replace('__DNS_PLACEHOLDER__', 'DNS = ' + dns);
        } else {
            conf = conf.replace(/__DNS_PLACEHOLDER__\n?/g, '');
        }
        conf = conf.replace(/__KEEPALIVE_PLACEHOLDER__|^PersistentKeepalive = .*/m, 'PersistentKeepalive = ' + ka);
        if (modalMode === 'add') {
            conf = conf.replace(/^#.*\n/, '');
            const desc = document.getElementById('peerDescription').value.trim();
            if (desc) {
                conf = '# ' + desc + '\n' + conf;
            }
        }

        document.getElementById('confText').value = conf;

        const canvas = document.getElementById('qrcode_canvas');
        canvas.innerHTML = '';
        if (privKey && privKey !== '<PASTE_PRIVATE_KEY_HERE>') {
            if (typeof QRCode !== 'undefined') {
                try {
                    new QRCode(canvas, {
                        text: conf,
                        width: 220,
                        height: 220,
                        colorDark: '#000',
                        colorLight: '#fff',
                        correctLevel: QRCode.CorrectLevel.H,
                        logo: '/wgx/qrlogo.png'
                    });
                } catch (e) {
                    console.error("QR Error", e);
                }
            } else {
                canvas.innerHTML = '<span class="text-danger">wg_qrcode.js not loaded</span>';
            }
        } else {
            canvas.innerHTML = '<small class="text-muted">Private key required<br>for QR generation</small>';
        }
    }

    function generateNewKeys() {
        fetch('/wgx/vpn_wg_export.php?action=gen_keys', { headers: { 'X-WGX-CSRF': getCsrf() } }).then(async r => {
            if (!r.ok) throw new Error(r.status);
            return r.json();
        }).then(data => {
            if (data.error) {
                alert('Key generation error: ' + data.error);
                return;
            }
            document.getElementById('clientPubKey').value = data.pub;
            document.getElementById('clientPrivKey').value = data.priv;

            // --- NEW: Auto-fill PSK if the checkbox is enabled ---
            if (document.getElementById('pskEnabled').checked && data.psk) {
                document.getElementById('clientPsk').value = data.psk;
            }
            // -----------------------------------------------------

            updateDisplays();
        }).catch(e => {
            alert('Server communication failed. ' + e.message);
        });
    }

    function refreshKeys() {
        generateNewKeys();
    }

    function refreshPsk() {
        fetch('/wgx/vpn_wg_export.php?action=gen_psk', { headers: { 'X-WGX-CSRF': getCsrf() } }).then(async r => {
            if (!r.ok) throw new Error(r.status);
            return r.json();
        }).then(data => {
            if (data.error) {
                alert('PSK error: ' + data.error);
                return;
            }
            document.getElementById('clientPsk').value = data.psk;
            updateDisplays();
        }).catch(e => {
            alert('Server communication failed. ' + e.message);
        });
    }

    function togglePsk(el) {
        document.getElementById('refreshPskBtn').disabled = !el.checked;
        if (el.checked) {
            refreshPsk();
        } else {
            document.getElementById('clientPsk').value = '';
            updateDisplays();
        }
    }

    function validatePeerForm() {
        const pub = document.getElementById('clientPubKey').value.trim();
        const desc = document.getElementById('peerDescription').value.trim();
        const ip = document.getElementById('peerAssignedIP').value.trim();
        if (!pub || !/^[A-Za-z0-9+\/]{43}=$/.test(pub)) {
            alert('Invalid public key.');
            return false;
        }
        if (!desc) {
            alert('Enter description.');
            return false;
        }
        if (!ip) {
            alert('Enter at least one IP/mask.');
            return false;
        }
        return true;
    }

    function wgxUpdateExpiry(val) {
        var infoDiv = document.getElementById('peerExpiryInfo');
        var infoText = document.getElementById('peerExpiryInfoText');
        var customRow = document.getElementById('peerExpiryCustomRow');
        var hiddenExp = document.getElementById('peerExpiryDate');
        if (val === '0') {
            hiddenExp.value = '0';
            infoDiv.style.display = 'none';
            customRow.style.display = 'none';
        } else if (val === 'custom') {
            hiddenExp.value = '0';
            customRow.style.display = '';
            infoDiv.style.display = 'none';
            document.getElementById('peerExpiryCustomDate').onchange = function() {
                var d = new Date(this.value);
                var now = new Date();
                var days = Math.round((d - now) / 86400000);
                hiddenExp.value = days > 0 ? days : '1';
                infoText.textContent = 'Expires ' + d.toLocaleDateString(undefined, {
                    weekday: 'long',
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                });
                infoDiv.style.display = '';
            };
        } else {
            var days = parseInt(val, 10);
            hiddenExp.value = days;
            customRow.style.display = 'none';
            var exp = new Date();
            exp.setDate(exp.getDate() + days);
            var label = days === 1 ? '1 day' : days < 30 ? days + ' days' : days < 365 ? Math.round(days / 30) + ' month(s)' : '1 year';
            infoText.textContent = label + ' — expires ' + exp.toLocaleDateString(undefined, {
                weekday: 'short',
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
            infoDiv.style.display = '';
        }
    }

    function wgxUpdateQuota(val) {
        var exemptField = document.getElementById('peerQuotaExempt');
        var limitField = document.getElementById('peerQuotaLimit');
        if (val === 'exempt') {
            exemptField.value = '1';
            limitField.value = '0';
        } else if (val === 'global') {
            exemptField.value = '0';
            limitField.value = '0';
        } else {
            exemptField.value = '0';
            limitField.value = val;
        }
    }

    function addPeerToTunnel() {
        if (!validatePeerForm()) return;
        const pub = document.getElementById('clientPubKey').value.trim();
        const priv = document.getElementById('clientPrivKey').value.trim();
        const desc = document.getElementById('peerDescription').value.trim();
        const ip = document.getElementById('peerAssignedIP').value.trim();
        const psk = document.getElementById('clientPsk').value.trim();
        const ka = document.getElementById('peerKeepAlive').value.trim();
        const exp = document.getElementById('peerExpiryDate') ? document.getElementById('peerExpiryDate').value.trim() : '0';
        const sched = document.getElementById('peerSchedule') ? document.getElementById('peerSchedule').value : 'always';
        const autoRot = document.getElementById('peerAutoRotate') ? document.getElementById('peerAutoRotate').value : '0';
        const quotaExempt = document.getElementById('peerQuotaExempt') ? document.getElementById('peerQuotaExempt').value : '1';
        const quotaLimit = document.getElementById('peerQuotaLimit') ? document.getElementById('peerQuotaLimit').value : '0';

        // NEW ZERO-TRUST VARIABLES
        const tier = document.getElementById('peerTier') ? document.getElementById('peerTier').value : 'admin';
        const target = document.getElementById('peerTarget') ? document.getElementById('peerTarget').value.trim() : '';

        const sel = document.getElementById('tunnelSelect');
        const tunName = sel.value;

        if (tier === 'vendor' && !target) {
            alert("Vendor Zero-Trust requires an Allowed Target (IP or Alias).");
            return;
        }

        if (!confirm(`Provision peer to "${tunName}" using policy: ${tier.toUpperCase()}?`)) return;
        const btn = document.getElementById('btnAddPeer');
        btn.disabled = true;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Saving…';

        const transport = 'standard';
        const peerEmail = document.getElementById('peerEmail') ? document.getElementById('peerEmail').value.trim() : '';
        const peerNotes = document.getElementById('peerNotes') ? document.getElementById('peerNotes').value.trim() : '';
        const body = new URLSearchParams({
            action: 'add_peer',
            __csrf_magic: getCsrf(),
                                         tun: tunName,
                                         publickey: pub,
                                             privatekey: priv,
                                                 descr: desc,
                                                 assignedip: ip,
                                                 presharedkey: psk,
                                                 keepalive: ka,
                                                 expiry: exp,
                                                 schedule: sched,
                                                 tier: tier,
                                                 target: target,
                                                 autorotate: autoRot,
                                                 quota_exempt: quotaExempt,
                                                 quota_limit_gb: quotaLimit,
                                                 transport: transport,
                                                 peer_email: peerEmail,
                                                 peer_notes: peerNotes,
                                                 peer_dns_override: document.getElementById('peerDNS') ? document.getElementById('peerDNS').value.trim() : '',
                                                 sched_date_from: document.getElementById('schedDateFrom') ? document.getElementById('schedDateFrom').value : '',
                                                 sched_date_to:   document.getElementById('schedDateTo')   ? document.getElementById('schedDateTo').value   : '',
                                                 peer_group: document.getElementById('peerGroup') ? document.getElementById('peerGroup').value.trim() : '',
                                                 offline_alert_hours: document.getElementById('peerOfflineAlert') ? document.getElementById('peerOfflineAlert').value : '0'
        });

        fetch('/wgx/vpn_wg_export.php', {
            method: 'POST',
            body
        }).then(async r => {
            if (!r.ok) {
                const txt = await r.text();
                if (txt.includes('<!DOCTYPE html>')) {
                    throw new Error("CSRF Token Expired or Session Timed Out. Please refresh the page.");
                }
                throw new Error("Server Error: " + r.status);
            }
            return r.json();
        }).then(data => {
            if (data.success) {
                alert(data.message);
                location.reload();
            } else {
                alert('Error: ' + data.message);
                btn.disabled = false;
                btn.innerHTML = 'Provision & Save';
            }
        }).catch(e => {
            alert(e.message);
            btn.disabled = false;
            btn.innerHTML = 'Provision & Save';
        });
    }

    // Tag filter state
    var activeTagFilter = '';

    function applyFilters() {
        var q = document.getElementById('searchPeers') ? document.getElementById('searchPeers').value.toLowerCase() : '';
        var groupFilter = document.getElementById('groupFilter') ? document.getElementById('groupFilter').value : '';
        document.querySelectorAll('#peersTable tbody tr').forEach(function(tr) {
            var textMatch = !q || tr.textContent.toLowerCase().includes(q);
            var tagMatch = true;
            if (activeTagFilter) {
                var rawTags = (tr.dataset.tags || '').split(',').map(function(t) {
                    return t.trim();
                });
                tagMatch = rawTags.indexOf(activeTagFilter.trim()) !== -1;
            }
            var groupMatch = !groupFilter || (tr.dataset.group || '') === groupFilter;
            tr.style.display = (textMatch && tagMatch && groupMatch) ? '' : 'none';
        });
    }

    function filterByTag(btn) {
        activeTagFilter = btn.dataset.tag;
        document.querySelectorAll('.tag-filter-btn').forEach(function(b) {
            b.classList.remove('active', 'btn-primary');
        });
        btn.classList.add('active');
        if (activeTagFilter) btn.classList.add('btn-primary');
        applyFilters();
    }

    function selectByActiveTag() {
        if (!activeTagFilter) return;
        document.querySelectorAll('#peersTable tbody tr').forEach(function(tr) {
            if (tr.style.display !== 'none') {
                var cb = tr.querySelector('.peer-checkbox');
                if (cb) cb.checked = true;
            }
        });
        updateBulkToolbar();
    }

    function openTagEditor(idx, currentTags) {
        var input = prompt('Edit tags (comma-separated, e.g. staff,contractors,iot):', currentTags);
        if (input === null) return;
        var body = new URLSearchParams({
            action: 'save_peer_tags',
            idx: idx,
            tags: input,
            __csrf_magic: getCsrf()
        });
        fetch('/wgx/vpn_wg_export.php', {
                method: 'POST',
                body: body
            })
            .then(function(r) {
                return r.json();
            })
            .then(function(data) {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(function(e) {
                alert('Request failed: ' + e.message);
            });
    }

    function closeModalAndReload() {
        $('#exportModal').modal('hide');
        location.reload();
    }

    // ── Live bandwidth chart ──────────────────────────────────────────────────
    var peerChartInstance = null;
    var peerGraphPubkey = '';
    var timelineLoaded = false;
    var bwPollTimer = null;
    var bwHistory = {
        labels: [],
        rx: [],
        tx: []
    };
    var BW_POLL_MS = 3000;
    var BW_MAX_POINTS = 60;

    function fmtBytes(b) {
        if (b == null || b < 0) return '-';
        if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
        if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
        if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
        return b + ' B';
    }

    function fmtMbps(m) {
        if (!m) return '0.000 Mbps';
        return m.toFixed(3) + ' Mbps';
    }

    function nowLabel() {
        var d = new Date();
        return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2);
    }

    function initBwChart() {
        if (peerChartInstance) {
            peerChartInstance.destroy();
            peerChartInstance = null;
        }
        var ctx = document.getElementById('peerBandwidthChart');
        if (!ctx || typeof Chart === 'undefined') return;
        peerChartInstance = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                        label: 'Rx (Mbps)',
                        data: [],
                        fill: true,
                        borderColor: 'rgba(92,184,92,1)',
                        backgroundColor: 'rgba(92,184,92,0.15)',
                        borderWidth: 2,
                        pointRadius: 0,
                        tension: 0.3
                    },
                    {
                        label: 'Tx (Mbps)',
                        data: [],
                        fill: true,
                        borderColor: 'rgba(91,192,222,1)',
                        backgroundColor: 'rgba(91,192,222,0.15)',
                        borderWidth: 2,
                        pointRadius: 0,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 200
                },
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            maxTicksLimit: 6
                        }
                    },
                    y: {
                        beginAtZero: true,
                        min: 0,
                        ticks: {
                            callback: function(v) {
                                return v.toFixed(2);
                            }
                        }
                    }
                }
            }
        });
    }

    function pushBwPoint(rxMbps, txMbps) {
        bwHistory.labels.push(nowLabel());
        bwHistory.rx.push(rxMbps);
        bwHistory.tx.push(txMbps);
        if (bwHistory.labels.length > BW_MAX_POINTS) {
            bwHistory.labels.shift();
            bwHistory.rx.shift();
            bwHistory.tx.shift();
        }
        if (!peerChartInstance) return;
        peerChartInstance.data.labels = bwHistory.labels;
        peerChartInstance.data.datasets[0].data = bwHistory.rx;
        peerChartInstance.data.datasets[1].data = bwHistory.tx;
        peerChartInstance.update('none');
    }

    function pollBw() {
        if (!peerGraphPubkey) return;
        fetch('/wgx/vpn_wg_export.php?action=get_peer_bw&pubkey=' + encodeURIComponent(peerGraphPubkey), { headers: { 'X-WGX-CSRF': getCsrf() } })
            .then(function(r) {
                return r.json();
            })
            .then(function(data) {
                if (!data.success) {
                    document.getElementById('bwPollStatus').textContent = 'Error: ' + (data.message || 'poll failed');
                    return;
                }
                var rxMbps = data.has_prev ? (data.rx_mbps || 0) : 0;
                var txMbps = data.has_prev ? (data.tx_mbps || 0) : 0;
                document.getElementById('bwStatRx').textContent = fmtMbps(rxMbps);
                document.getElementById('bwStatTx').textContent = fmtMbps(txMbps);
                document.getElementById('bwStatTotalRx').textContent = fmtBytes(data.rx_bytes);
                document.getElementById('bwStatTotalTx').textContent = fmtBytes(data.tx_bytes);
                document.getElementById('peerGraphNoData').style.display = (!data.found || (data.rx_bytes === 0 && data.tx_bytes === 0)) ? '' : 'none';
                if (!data.has_prev) {
                    document.getElementById('bwPollStatus').textContent = 'Calibrating... (first reading)';
                } else {
                    document.getElementById('bwPollStatus').textContent = 'Live - last update ' + nowLabel();
                    pushBwPoint(rxMbps, txMbps);
                }
            }).catch(function() {
                document.getElementById('bwPollStatus').textContent = 'Poll error - retrying...';
            });
    }

    function openPeerGraph(pubkey, name) {
        peerGraphPubkey = pubkey;
        timelineLoaded = false;
        document.getElementById('peerGraphTitle').textContent = name;
        bwHistory = {
            labels: [],
            rx: [],
            tx: []
        };
        ['bwStatRx', 'bwStatTx', 'bwStatTotalRx', 'bwStatTotalTx'].forEach(function(id) {
            document.getElementById(id).textContent = '-';
        });
        document.getElementById('bwPollStatus').textContent = 'Starting...';
        document.getElementById('peerGraphNoData').style.display = 'none';
        if (bwPollTimer) {
            clearInterval(bwPollTimer);
            bwPollTimer = null;
        }
        $('#peerGraphModal').one('shown.bs.modal', function() {
            initBwChart();
            pollBw();
            bwPollTimer = setInterval(pollBw, BW_POLL_MS);
        });
        $('#peerGraphModal').modal('show');
    }
    $('#peerGraphModal').on('hidden.bs.modal', function() {
        if (bwPollTimer) {
            clearInterval(bwPollTimer);
            bwPollTimer = null;
        }
        if (peerChartInstance) {
            peerChartInstance.destroy();
            peerChartInstance = null;
        }
    });

    function onTimelineTab() {
        if (timelineLoaded) return;
        timelineLoaded = true;
        var listEl = document.getElementById('peerTimelineList');
        var loadEl = document.getElementById('peerTimelineLoading');
        var errEl = document.getElementById('peerTimelineError');
        var contEl = document.getElementById('peerTimelineContent');
        fetch('/wgx/vpn_wg_export.php?action=get_peer_history&pubkey=' + encodeURIComponent(peerGraphPubkey), { headers: { 'X-WGX-CSRF': getCsrf() } })
            .then(function(r) {
                return r.json();
            })
            .then(function(data) {
                loadEl.style.display = 'none';
                if (!data.success) {
                    errEl.textContent = data.message || 'Failed';
                    errEl.style.display = '';
                    return;
                }
                listEl.innerHTML = '';
                if (!data.events || !data.events.length) {
                    listEl.innerHTML = '<li class="text-muted text-center" style="padding:20px;">No recorded activity yet.</li>';
                } else {
                    data.events.forEach(function(ev) {
                        var li = document.createElement('li');
                        li.style.cssText = 'padding:6px 0;border-bottom:1px solid #f0f0f0';
                        li.innerHTML = '<span class="text-muted" style="font-size:11px;">' + ev.time + '</span> ' + ev.msg;
                        listEl.appendChild(li);
                    });
                }
                contEl.style.display = '';
            }).catch(function() {
                loadEl.style.display = 'none';
                errEl.textContent = 'Timeline load failed.';
                errEl.style.display = '';
            });
    }

    function downloadConfFile() {
        if (modalMode === 'add' && !validatePeerForm()) return;
        const desc = modalMode === 'add' ? document.getElementById('peerDescription').value.trim() : currentPeerName;
        let ext = (typeof exportFormat !== 'undefined' && exportFormat === 's2s') ? '.txt' : '.conf';
        const fileName = desc.replace(/[^a-zA-Z0-9_-]/g, '_') + ext;

        const blob = new Blob([document.getElementById('confText').value], {
            type: 'application/octet-stream'
        });
        const a = Object.assign(document.createElement('a'), {
            href: URL.createObjectURL(blob),
            download: fileName
        });
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
    }


    // ── Migrate to WebSocket modal ────────────────────────────────────────────
    var migrateCurrentIdx = null;
    var migrateCurrentName = null;

    function openMigrateModal(idx, name, wsTunList) {
        migrateCurrentIdx = idx;
        migrateCurrentName = name;
        var tunList = Array.isArray(wsTunList) ? wsTunList : [wsTunList];
        document.getElementById('migratePeerName').textContent = name;
        var sel = document.getElementById('migrateTunSelect');
        sel.innerHTML = '';
        tunList.forEach(function(t) {
            var o = document.createElement('option');
            o.value = t;
            o.textContent = t;
            sel.appendChild(o);
        });
        document.getElementById('migrateResult').style.display = 'none';
        document.getElementById('migrateResultText').textContent = '';
        document.getElementById('btnConfirmMigrate').disabled = false;
        document.getElementById('btnConfirmMigrate').innerHTML = '<i class="fa fa-exchange"></i> Migrate';
        $('#migrateModal').modal('show');
    }

    function confirmMigrate() {
        var btn = document.getElementById('btnConfirmMigrate');
        var result = document.getElementById('migrateResult');
        var text = document.getElementById('migrateResultText');
        var dstTun = document.getElementById('migrateTunSelect').value;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Migrating...';
        var body = new URLSearchParams({
            action: 'migrate_peer_to_ws',
            src_idx: migrateCurrentIdx,
            dst_tun: dstTun,
            __csrf_magic: getCsrf()
        });
        fetch('/wgx/vpn_wg_export.php', {
                method: 'POST',
                body: body
            })
            .then(function(r) {
                return r.json();
            })
            .then(function(data) {
                result.className = 'alert ' + (data.success ? 'alert-success' : 'alert-danger');
                text.textContent = data.message || (data.success ? 'Migrated.' : 'Failed.');
                result.style.display = '';
                btn.innerHTML = '<i class="fa fa-exchange"></i> Migrate';
                if (data.success) {
                    btn.disabled = true;
                    setTimeout(function() {
                        location.reload();
                    }, 1800);
                } else {
                    btn.disabled = false;
                }
            })
            .catch(function() {
                result.className = 'alert alert-danger';
                text.textContent = 'Request failed.';
                result.style.display = '';
                btn.disabled = false;
                btn.innerHTML = '<i class="fa fa-exchange"></i> Migrate';
            });
    }

            // ── Duplicate peer name check ────────────────────────────────────────────
    function checkDuplicateName(val) {
        if (!val) { document.getElementById('peerNameDupWarn').style.display = 'none'; return; }
        const lower = val.toLowerCase().trim();
        const rows = document.querySelectorAll('#peersTable tbody tr');
        let dup = false;
        rows.forEach(function(tr) {
            const nameCell = tr.querySelector('td:nth-child(3) strong');
            if (nameCell && nameCell.textContent.trim().toLowerCase() === lower) dup = true;
        });
        document.getElementById('peerNameDupWarn').style.display = dup ? '' : 'none';
    }

    // ── Clipboard copy for conf text ─────────────────────────────────────────
    function copyConfToClipboard() {
        const ta = document.getElementById('confText');
        if (!ta) return;
        navigator.clipboard.writeText(ta.value).then(function() {
            const btn = ta.parentNode.querySelector('button[onclick*="copyConf"]');
            if (btn) { btn.innerHTML = '<i class="fa fa-check"></i>'; setTimeout(() => btn.innerHTML = '<i class="fa fa-clipboard"></i>', 2000); }
        }).catch(function() {
            ta.select(); document.execCommand('copy');
        });
    }

    // ── Ping test ────────────────────────────────────────────────────────────
    function pingPeer(peerIp, peerName, btn) {
        if (!peerIp || peerIp === '—') { alert('No tunnel IP available for ' + peerName); return; }
        // Strip CIDR notation and use first IP only
        const ip = peerIp.split(',')[0].split('/')[0].trim();
        if (!ip) { alert('No valid IP for ' + peerName); return; }
        const body = new URLSearchParams({ action: 'ping_peer', peer_ip: ip, __csrf_magic: getCsrf() });
        const oldHtml = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i>'; }
        fetch('/wgx/vpn_wg_export.php', { method: 'POST', body })
            .then(r => r.json())
            .then(data => {
                if (btn) { btn.disabled = false; btn.innerHTML = oldHtml; }
                const icon = data.reachable ? '✅' : '❌';
                const status = data.reachable ? 'Reachable' : 'Unreachable';
                alert(icon + ' ' + peerName + ' (' + ip + '): ' + status + '\n\n' + (data.output || 'No output'));
            })
            .catch(e => {
                if (btn) { btn.disabled = false; btn.innerHTML = oldHtml; }
                alert('Ping failed: ' + e.message);
            });
    }

    // ── QR expiry notice ─────────────────────────────────────────────────────
    function updateQrExpiryNotice(confTokenFresh) {
        const el = document.getElementById('qrExpiryNotice');
        if (el) el.style.display = confTokenFresh ? 'none' : '';
    }

    // ── Populate group datalist suggestions ──────────────────────────────────
    (function() {
        const dl = document.getElementById('peerGroupSuggestions');
        if (!dl) return;
        const groups = new Set();
        document.querySelectorAll('[data-group]').forEach(el => { if (el.dataset.group) groups.add(el.dataset.group); });
        groups.forEach(g => { const opt = document.createElement('option'); opt.value = g; dl.appendChild(opt); });
    })();

    <?php if ($auto_open_idx !== null): ?>
document.addEventListener('DOMContentLoaded', () => {
            openExportModal(<?= (int) $auto_open_idx ?>, <?= json_encode(
                                                                $auto_open_name,
                                                                JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT
                                                            ) ?>);
        });
    <?php endif; ?>
</script>
<?php include "foot.inc"; ?>
