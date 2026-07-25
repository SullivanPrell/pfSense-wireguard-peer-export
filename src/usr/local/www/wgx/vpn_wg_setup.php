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
        // Match rules created by WG Suite deploy
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
            'savemsg' => $savemsg,
        ];
        // Fire-and-forget the slow stuff after we send the response.
        wgx_schedule_post_response_tasks();

        // Streaming mode: tell the client we're done and where to go next.
        // No Location: header — the client navigates on receiving 'done'.
        if ($GLOBALS['wgx_stream_mode']) {
            wgx_stream_event('done', [
                'navigate'    => 'vpn_wg_setup.php?deployed=1',
                'port_change' => false,
                'new_port'    => 0,
                'message'     => $savemsg,
            ]);
            exit;
        }

        header('Location: vpn_wg_setup.php?deployed=1');
        exit;
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
        unset($_SESSION['wgx_setup_result']);
    }
}

// ── Deferred post-response tasks ───────────────────────────────────────
// These happen AFTER the browser has the redirect. Uses
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
        });
    }

})();
</script>

<?php include("foot.inc"); ?>
