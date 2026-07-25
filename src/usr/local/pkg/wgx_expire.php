#!/usr/local/bin/php -q
<?php
/*
 * wgx_expire.php
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

// === 2.A. Daemon Init ===
require_once("config.inc");
require_once("util.inc");
require_once("pkg-utils.inc");

define('WGX_VERSION', '1.2.0');

$lock_file = '/tmp/wgx_expire.lock';
if (file_exists($lock_file) && (time() - filemtime($lock_file)) < 300) {
    exit(0);
}
touch($lock_file);
register_shutdown_function(function() use ($lock_file) {
    unlink_if_exists($lock_file);
});

$now          = time();
$changed      = false;
$alias_changed = false;

// === 2.B. Peer Expiration & Time-Based Scheduling ===
$current_day  = (int)date('N'); // ISO-8601: 1=Monday, 7=Sunday
$current_hour = (int)date('G'); // 0-23

// Load peers once — reused by expiry, scheduling, AD sync, and quota sections
$a_peers = config_get_path('installedpackages/wireguard/peers/item', []);
if (is_array($a_peers)) {
    foreach ($a_peers as &$peer) {
        // 1. Hard Expiration (top priority)
        if (isset($peer['enabled']) && $peer['enabled'] === 'yes' && !empty($peer['expire_time'])) {

            // Expiry warning — send once when within 24 hours of expiry
            $expires_in = (int)$peer['expire_time'] - $now;
            if ($expires_in > 0 && $expires_in <= 86400 && empty($peer['wgx_expiry_warned'])) {
                $peer['wgx_expiry_warned'] = '1';
                $changed = true;
                $warn_descr = $peer['descr'] ?? 'Unknown';
                $warn_tun   = $peer['tun']   ?? 'Unknown';
                syslog(LOG_NOTICE, "WG Suite: Peer '{$warn_descr}' expires in " . round($expires_in / 3600) . "h");
                if (!function_exists('send_smtp_message')) {
                    @include_once('/etc/inc/notify.inc');
                }
                if (function_exists('send_smtp_message') &&
                    !empty(config_get_path('notifications/smtp/ipaddress'))) {
                    @send_smtp_message(
                        "WG Suite Automated Notice\n\nPeer '{$warn_descr}' on tunnel {$warn_tun} will expire in approximately " . round($expires_in / 3600) . " hour(s) at " . date('Y-m-d H:i:s T', (int)$peer['expire_time']) . ".\n\nYou can extend or remove the expiry from the WG Suite Export page.\n",
                                       "WG Suite: Peer '{$warn_descr}' expires soon"
                    );
                    }
            }

            if ($now > (int)$peer['expire_time']) {
                $peer['enabled'] = 'no';
                $changed = true;
                $descr_exp = $peer['descr'] ?? 'Unknown';
                $tun_exp   = $peer['tun']   ?? 'Unknown';
                syslog(LOG_NOTICE, "WG Suite: Auto-disabled expired peer '{$descr_exp}' on {$tun_exp}");

                // Email notification to admin notify address
                if (!function_exists('send_smtp_message')) {
                    @include_once('/etc/inc/notify.inc');
                }
                if (function_exists('send_smtp_message') &&
                    !empty(config_get_path('notifications/smtp/ipaddress'))) {
                    $exp_subject = "WG Suite: Peer '{$descr_exp}' has expired";
                    $exp_body    = "WG Suite Automated Notice

"
                        . "The following WireGuard peer has reached its expiry time and has been automatically disabled:

"
                        . "  Peer:    {$descr_exp}
"
                        . "  Tunnel:  {$tun_exp}
"
                        . "  Expired: " . date('Y-m-d H:i:s T') . "

"
                        . "You can re-enable or delete this peer from the WG Suite Export page.
";
                    @send_smtp_message($exp_body, $exp_subject);
                }
                continue;
            }
        }

        // 2. Dynamic Schedule Toggling
        $schedule         = $peer['wgx_schedule'] ?? 'always';
        $is_enabled       = (isset($peer['enabled']) && $peer['enabled'] === 'yes');
        $should_be_enabled = true;

        // Business hours boundaries — configurable in Global Settings, defaulting to 09:00–17:00
        $biz_start = (int)($wgx_settings['business_hours_start'] ?? 9);
        $biz_end   = (int)($wgx_settings['business_hours_end']   ?? 17);

        if ($schedule === 'business' || $schedule === 'business_hours') {
            // Mon–Fri, within configured business hours
            $should_be_enabled = ($current_day >= 1 && $current_day <= 5 && $current_hour >= $biz_start && $current_hour < $biz_end);
        } elseif ($schedule === 'weekday' || $schedule === 'weekdays') {
            $should_be_enabled = ($current_day >= 1 && $current_day <= 5);
        } elseif ($schedule === 'weekend' || $schedule === 'weekends') {
            $should_be_enabled = ($current_day == 6 || $current_day == 7);
        } elseif ($schedule === 'nights') {
            // Outside configured business hours on any day
            $should_be_enabled = !($current_hour >= $biz_start && $current_hour < $biz_end);
        }

        // Date range schedule
        if ($schedule === 'date_range') {
            $from_str = $peer['wgx_sched_from'] ?? '';
            $to_str   = $peer['wgx_sched_to']   ?? '';
            $from_ts  = !empty($from_str) ? (strtotime($from_str . ' 00:00:00') ?: 0) : 0;
            $to_ts    = !empty($to_str)   ? (strtotime($to_str   . ' 23:59:59') ?: PHP_INT_MAX) : PHP_INT_MAX;
            $should_be_enabled = ($from_ts === 0 || $now >= $from_ts) && ($to_ts === PHP_INT_MAX || $now <= $to_ts);
        }

        if ($schedule !== 'always') {
            if ($should_be_enabled && !$is_enabled && empty($peer['expire_time'])) {
                $peer['enabled'] = 'yes';
                $changed = true;
                syslog(LOG_NOTICE, "WG Suite: Schedule ('{$schedule}') starting - Enabled peer '{$peer['descr']}'");
            } elseif (!$should_be_enabled && $is_enabled) {
                $peer['enabled'] = 'no';
                $changed = true;
                syslog(LOG_NOTICE, "WG Suite: Schedule ('{$schedule}') ended - Disabled peer '{$peer['descr']}'");
            }
        }
    }
    unset($peer);
    if ($changed) {
        config_set_path('installedpackages/wireguard/peers/item', $a_peers);
    }
}

// === 2.C. AD Identity Sync ===
$system_users    = config_get_path('system/user', []);
$active_usernames = [];
foreach ($system_users as $su) {
    if (!isset($su['disabled'])) {
        $active_usernames[] = strtolower($su['name']);
    }
}

// $a_peers already loaded above — reuse it
if (is_array($a_peers)) {
    $ad_changed = false;
    foreach ($a_peers as &$peer) {
        if (isset($peer['enabled']) && $peer['enabled'] === 'yes' &&
            strpos(strtolower($peer['descr']), 'ad_sync:') === 0) {
            $mapped_user = trim(substr(strtolower($peer['descr']), 8));
        if (!in_array($mapped_user, $active_usernames)) {
            $peer['enabled'] = 'no';
            $ad_changed      = true;
            $changed         = true;
        }
            }
    }
    unset($peer);
    if ($ad_changed) {
        config_set_path('installedpackages/wireguard/peers/item', $a_peers);
    }
}

// === 2.D. Telemetry Archiving ===
$archive = []; // Initialise before the wg transfer block so quota check always has it
// even when wg produces no transfer output.
$wg_bin  = is_executable('/usr/local/bin/wg') ? '/usr/local/bin/wg' : '/usr/bin/wg';
if (!empty($wg_bin)) {
    $out = [];
    exec(escapeshellarg($wg_bin) . ' show all transfer 2>/dev/null', $out);
    $rawTx = implode("\n", $out);
    if ($rawTx) {
        $archive_file    = '/var/db/wgx_telemetry_archive.json';
        $archive         = file_exists($archive_file) ? (json_decode(file_get_contents($archive_file), true) ?? []) : [];
        $current_hour_ts = strtotime(date('Y-m-d H:00:00'));

        foreach (explode("\n", $rawTx) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) >= 4) {
                $pub = $parts[1];
                $rx  = (int)$parts[2];
                $tx  = (int)$parts[3];

                if (!isset($archive[$pub])) {
                    $archive[$pub] = ['rx' => 0, 'tx' => 0, 'last_seen' => 0, 'history' => []];
                }

                if ($rx > 0 || $tx > 0) {
                    $archive[$pub]['rx']        = $rx;
                    $archive[$pub]['tx']        = $tx;
                    $archive[$pub]['last_seen'] = $now;

                    if (!isset($archive[$pub]['history'])) {
                        $archive[$pub]['history'] = [];
                    }
                    $prev = $archive[$pub]['history'][$current_hour_ts] ?? ['rx' => 0, 'tx' => 0];
                    $archive[$pub]['history'][$current_hour_ts] = [
                        'rx' => max($rx, is_array($prev) ? (int)$prev['rx'] : 0),
                        'tx' => max($tx, is_array($prev) ? (int)$prev['tx'] : 0),
                    ];

                    foreach ($archive[$pub]['history'] as $ts => $val) {
                        if ((int)$ts < ($now - 86400)) {
                            unset($archive[$pub]['history'][$ts]);
                        }
                    }
                }
            }
        }
        file_put_contents($archive_file, json_encode($archive));
    }
}

// === 2.D.1. Automated Bandwidth Throttling (QoS Alias) ===
$wgx_settings    = config_get_path('installedpackages/wgexport/config/0', []);
$quota_limit_gb   = max(1, (int)($wgx_settings['quota_limit_gb'] ?? 100));
$quota_limit_bytes = $quota_limit_gb * 1024 * 1024 * 1024;
$throttled_ips    = [];

$a_peers = config_get_path('installedpackages/wireguard/peers/item', []);
if (is_array($a_peers)) {
    foreach ($a_peers as $peer) {
        $pub = $peer['publickey'] ?? '';
        // Honour the quota-exempt flag set at creation or via the NOC Dashboard
        if (($peer['wgx_quota_exempt'] ?? '0') === '1') continue;
        // Per-peer quota limit overrides the global setting (0 = use global)
        $peer_quota_gb    = (int)($peer['wgx_quota_limit_gb'] ?? 0);
        $peer_quota_bytes = $peer_quota_gb > 0
            ? $peer_quota_gb * 1024 * 1024 * 1024
            : $quota_limit_bytes;
        if (!empty($pub) && isset($archive[$pub])) {
            $total_usage = ($archive[$pub]['rx'] ?? 0) + ($archive[$pub]['tx'] ?? 0);
            if ($total_usage > $peer_quota_bytes) {
                $allowedips    = isset($peer['allowedips']) && is_array($peer['allowedips']) ? $peer['allowedips'] : [];
                $raw_allowedips = $allowedips['row'] ?? ($allowedips['item'] ?? []);
                if (is_array($raw_allowedips) && !empty($raw_allowedips)) {
                    $rows = isset($raw_allowedips['address']) ? [$raw_allowedips] : $raw_allowedips;
                    foreach ($rows as $row) {
                        if (is_array($row) && !empty($row['address'])) {
                            $throttled_ips[] = $row['address'];
                        }
                    }
                }
            }
        }
    }
}

// Update the pfSense Alias for Throttled IPs
$all_aliases = config_get_path('aliases/alias', []);
$alias_idx   = -1;
foreach ($all_aliases as $idx => $alias) {
    if (($alias['name'] ?? '') === 'WGX_THROTTLED') {
        $alias_idx = $idx;
        break;
    }
}

$unique_ips = array_unique($throttled_ips);
$alias_data = [
    'name'    => 'WGX_THROTTLED',
'type'    => 'host',
'address' => implode(' ', $unique_ips),
'descr'   => 'WG Suite: Auto-managed list of peers exceeding ' . $quota_limit_gb . 'GB bandwidth quota',
'detail'  => implode('||', array_fill(0, count($unique_ips), 'Auto-Throttled')),
];

if ($alias_idx >= 0) {
    if (($all_aliases[$alias_idx]['address'] ?? '') !== $alias_data['address']) {
        $all_aliases[$alias_idx] = $alias_data;
        $alias_changed = true;
    }
} else {
    $all_aliases[] = $alias_data;
    $alias_changed = true;
}

if ($alias_changed) {
    config_set_path('aliases/alias', $all_aliases);
    $changed = true;
    syslog(LOG_NOTICE, "WG Suite: Updated WGX_THROTTLED alias for QoS (" . count($unique_ips) . " peers throttled).");
}

// === 2.E. IP Reputation & Geolocation ===
// Only runs if user has opted in via Global Settings
$geo_enabled = ($wgx_settings['enable_geo'] ?? 'false') === 'true';

if ($geo_enabled) {
    $rep_file      = '/var/db/wgx_ip_reputation.json';
    $tor_list_file = '/var/db/wgx_tor_exits.txt';
    $rep_data      = file_exists($rep_file) ? (json_decode(file_get_contents($rep_file), true) ?? []) : [];

    // Refresh Tor exit node list once per day
    if (!file_exists($tor_list_file) || (time() - filemtime($tor_list_file)) > 86400) {
        $ctx     = stream_context_create(['http' => ['timeout' => 10, 'user_agent' => 'WGSuite/1.2'], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $tor_raw = @file_get_contents('https://check.torproject.org/torbulkexitlist', false, $ctx);
        if ($tor_raw) {
            file_put_contents($tor_list_file, $tor_raw);
        }
    }
    $tor_exits = file_exists($tor_list_file)
    ? array_flip(array_filter(array_map('trim', file($tor_list_file))))
    : [];

    // Get live peer endpoints
    $ep_out = [];
    exec(escapeshellarg($wg_bin) . ' show all endpoints 2>/dev/null', $ep_out);
    $peer_endpoint_map = [];
    foreach ($ep_out as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) >= 3 && $parts[2] !== '(none)') {
            $pub = $parts[1];
            $ep  = $parts[2];
        } elseif (count($parts) === 2 && $parts[1] !== '(none)') {
            $pub = $parts[0];
            $ep  = $parts[1];
        } else {
            continue;
        }
        $last_colon = strrpos($ep, ':');
        $ip = $last_colon !== false ? trim(substr($ep, 0, $last_colon), '[]') : $ep;
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
            $peer_endpoint_map[$pub] = $ip;
        }
    }

    // Build pubkey => descr map
    $peer_descr_map = [];
    $a_peers_rep    = config_get_path('installedpackages/wireguard/peers/item', []);
    foreach ($a_peers_rep as $p) {
        if (!empty($p['publickey'])) {
            $peer_descr_map[$p['publickey']] = $p['descr'] ?? 'Unknown';
        }
    }

    foreach ($peer_endpoint_map as $pubkey => $ip) {
        // Skip if checked recently (10 min)
        if (isset($rep_data[$ip]['checked']) && (time() - $rep_data[$ip]['checked']) < 600) {
            continue;
        }

        $flags = [];
        $isp   = '';
        $org   = '';
        $lat   = null;
        $lon   = null;
        $city  = '';
        $country      = '';
        $country_code = '';

        if (isset($tor_exits[$ip])) {
            $flags[] = 'tor';
        }

        $ctx_api = stream_context_create(['http' => ['timeout' => 5, 'user_agent' => 'WGSuite/1.2']]);
        $api_raw = @file_get_contents(
            "https://ip-api.com/json/{$ip}?fields=proxy,hosting,isp,org,status,lat,lon,city,country,countryCode",
            false,
            $ctx_api
        );
        if ($api_raw) {
            $api = json_decode($api_raw, true);
            if (is_array($api) && ($api['status'] ?? '') === 'success') {
                if (!empty($api['proxy']))   { $flags[] = 'proxy'; }
                if (!empty($api['hosting'])) { $flags[] = 'hosting'; }
                $isp          = $api['isp']         ?? '';
                $org          = $api['org']         ?? '';
                $lat          = $api['lat']         ?? null;
                $lon          = $api['lon']         ?? null;
                $city         = $api['city']        ?? '';
                $country      = $api['country']     ?? '';
                $country_code = $api['countryCode'] ?? '';
            }
        }

        $rep_data[$ip] = [
            'flags'        => $flags,
            'isp'          => $isp,
            'org'          => $org,
            'lat'          => $lat,
            'lon'          => $lon,
            'city'         => $city,
            'country'      => $country,
            'country_code' => $country_code,
            'checked'      => time(),
        ];

        if (!empty($flags)) {
            $descr = $peer_descr_map[$pubkey] ?? $pubkey;
            syslog(LOG_WARNING, "WG Suite: IP Reputation Alert - Peer '{$descr}' connecting from {$ip} flagged as: "
            . implode(', ', array_map('strtoupper', $flags)));
        }
    }

    if (!empty($peer_endpoint_map)) {
        file_put_contents($rep_file, json_encode($rep_data, JSON_PRETTY_PRINT));
    }
}

// === 2.F. Monthly Bandwidth Report ===
// Generates a CSV summary on the 1st of each month at the first cron run
$report_dir = '/var/db/wgx_reports';
$report_flag = $report_dir . '/last_report_month.txt';
$current_month = date('Y-m');
$last_month = file_exists($report_flag) ? trim(file_get_contents($report_flag)) : '';

if ($current_month !== $last_month) {
    if (!is_dir($report_dir)) @mkdir($report_dir, 0700, true);

    $report_peers = config_get_path('installedpackages/wireguard/peers/item', []);
    $prev_month = date('Y-m', strtotime('-1 month'));
    $report_file = $report_dir . '/wgx_bw_report_' . $prev_month . '.csv';

    $lines = ["Peer,Tunnel,Rx (MB),Tx (MB),Total (MB),Quota (GB),Quota Used %"];
    $global_quota = max(1, (int)(config_get_path('installedpackages/wgexport/config/0/quota_limit_gb', 100)));

    foreach ($report_peers as $rp) {
        if (!is_array($rp)) continue;
        $pub   = $rp['publickey'] ?? '';
        $descr = $rp['descr'] ?? 'Unknown';
        $tun   = $rp['tun']   ?? 'Unknown';
        $quota = (int)($rp['wgx_quota_limit_gb'] ?? 0) ?: $global_quota;
        $exempt = ($rp['wgx_quota_exempt'] ?? '0') === '1';

        // Pull from archive if available
        $arch_rx = 0; $arch_tx = 0;
        if (!empty($pub) && !empty($archive[$pub]['history'])) {
            foreach ($archive[$pub]['history'] as $val) {
                $arch_rx = max($arch_rx, (int)($val['rx'] ?? 0));
                $arch_tx = max($arch_tx, (int)($val['tx'] ?? 0));
            }
        }
        $rx_mb    = round($arch_rx / 1048576, 2);
        $tx_mb    = round($arch_tx / 1048576, 2);
        $total_mb = $rx_mb + $tx_mb;
        $quota_pct = $exempt ? 'Exempt' : round($total_mb / ($quota * 1024) * 100, 1) . '%';

        $lines[] = implode(',', [
            '"' . str_replace('"', '""', $descr) . '"',
            '"' . str_replace('"', '""', $tun) . '"',
            $rx_mb, $tx_mb, $total_mb,
            $exempt ? 'Exempt' : $quota,
            $quota_pct
        ]);
    }

    file_put_contents($report_file, implode("
", $lines), LOCK_EX);
    file_put_contents($report_flag, $current_month, LOCK_EX);
    syslog(LOG_NOTICE, "WG Suite: Monthly bandwidth report generated: {$report_file}");

    // Send report via webhook if configured
    if (function_exists('wgx_send_webhook')) {
        wgx_send_webhook('quota', "Monthly bandwidth report for {$prev_month} generated. File: {$report_file}", ['month' => $prev_month]);
    }
}

// === 2.G. Daemon Footer & Runtime Refresh ===
if ($changed) {
    write_config("WG Suite: Automated peer management (expiry/scheduling/AD sync)");

    if (function_exists('mark_subsystem_dirty')) {
        mark_subsystem_dirty('wireguard');
    }

    try {
        foreach ([
            '/usr/local/pkg/wireguard/includes',
            '/usr/local/pkg/wireguard-kmod/includes',
            '/usr/local/share/pfSense/pkg/wireguard/includes',
        ] as $_wg_inc) {
            @include_once("{$_wg_inc}/wg_globals.inc");
            @include_once("{$_wg_inc}/wg.inc");
            @include_once("{$_wg_inc}/wg_service.inc");
            if (function_exists('wg_resync') || function_exists('setup_wg')) break;
        }
        unset($_wg_inc);

        if (function_exists('wg_tunnel_sync')) {
            wg_tunnel_sync();
        } elseif (function_exists('setup_wg')) {
            setup_wg();
        }
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'WG Suite: Runtime refresh failed — ' . $e->getMessage());
    }

    if ($alias_changed && function_exists('filter_configure')) {
        filter_configure();
    }
}

// Lock file cleanup handled by register_shutdown_function above
