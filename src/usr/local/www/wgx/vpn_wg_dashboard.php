<?php
/*
 * vpn_wg_dashboard.php
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

require_once("guiconfig.inc");
require_once("util.inc");
require_once("pkg-utils.inc");

// === Helper: Config Array Reader ===
function wgx_get_config_array_dash($type) {
    $type_plural = $type . 's';
    $data = config_get_path("installedpackages/wireguard/{$type_plural}/item", []);
    if (!is_array($data)) { $data = []; }
    if (!empty($data) && !isset($data[0])) { $data = [$data]; }
    return $data;
}

// === Helper: Resolve a tunnel's IPv4 address + mask (multi-tier) ===
// Tier 1 (kernel): what the interface actually carries right now, via
//   pfSense_get_ifaddrs() — the same call the native WireGuard package
//   uses in wg_interface_update_addresses() — falling back to parsing
//   ifconfig output. Works for assigned AND unassigned tunnels.
// Tier 2 (tunnel config): the tunnel's Interface Addresses rows at
//   installedpackages/wireguard/tunnels/item[]/addresses/row[]. The native
//   package only honours these for UNASSIGNED tunnels and seeds assigned
//   tunnels with an empty row, so blank addresses are skipped.
// Tier 3 (pfSense interface): the assigned OPT interface's static config
//   (interfaces/<opt>/ipaddr + subnet).
// Prefers the first tier yielding a peer-capable subnet (mask <= 30);
// otherwise returns the first candidate (e.g. a /31 point-to-point).
// Returns ['ip','mask','source'] or null.
function wgx_dash_tunnel_ipv4($t, $cfg_ifaces) {
    $cands  = [];
    $t_name = trim($t['name'] ?? '');
    // Tier 1: kernel
    if ($t_name !== '') {
        if (function_exists('pfSense_get_ifaddrs')) {
            $ifa = @pfSense_get_ifaddrs($t_name);
            if (is_array($ifa)) {
                foreach ((array)($ifa['addrs'] ?? []) as $a) {
                    if (!empty($a['addr']) && isset($a['subnetbits']) &&
                        filter_var($a['addr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $cands[] = ['ip' => $a['addr'], 'mask' => (int)$a['subnetbits'], 'source' => 'kernel'];
                        break;
                    }
                }
            }
        }
        if (empty($cands)) {
            $ifc_out = [];
            @exec('/sbin/ifconfig ' . escapeshellarg($t_name) . ' 2>/dev/null', $ifc_out);
            foreach ($ifc_out as $ifc_line) {
                if (preg_match('/inet\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+-->\s+\S+)?\s+netmask\s+(0x[0-9a-fA-F]{1,8})/', $ifc_line, $m)) {
                    $km = substr_count(sprintf('%032b', hexdec($m[2])), '1');
                    $cands[] = ['ip' => $m[1], 'mask' => $km, 'source' => 'kernel'];
                    break;
                }
            }
        }
    }
    // Tier 2: tunnel config rows (native schema, unassigned tunnels)
    $t_addrs = (array)($t['addresses'] ?? []);
    $t_rows  = $t_addrs['row'] ?? ($t_addrs['item'] ?? []);
    if (is_array($t_rows) && !empty($t_rows)) {
        $rows = isset($t_rows['address']) ? [$t_rows] : $t_rows;
        foreach ($rows as $r) {
            if (is_array($r) && !empty($r['address']) &&
                filter_var(trim($r['address']), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $cands[] = ['ip' => trim($r['address']), 'mask' => (int)($r['mask'] ?? 24), 'source' => 'tunnel-config'];
                break;
            }
        }
    }
    // Tier 3: assigned pfSense interface (static IPv4)
    if ($t_name !== '' && is_array($cfg_ifaces)) {
        foreach ($cfg_ifaces as $if_ent) {
            if (is_array($if_ent) && trim($if_ent['if'] ?? '') === $t_name &&
                !empty($if_ent['ipaddr']) &&
                filter_var($if_ent['ipaddr'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $cands[] = ['ip' => $if_ent['ipaddr'], 'mask' => (int)($if_ent['subnet'] ?? 24), 'source' => 'pfsense-interface'];
                break;
            }
        }
    }
    foreach ($cands as $c) {
        if ($c['mask'] >= 0 && $c['mask'] <= 30) { return $c; }
    }
    return !empty($cands) ? $cands[0] : null;
}

// === POST: Set Quota Exemption ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'set_quota_exempt') {
    if (!csrf_check(false)) {
        header('Content-Type: application/json'); http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'CSRF validation failed.']); exit;
    }
    $pub    = trim($_POST['pub']  ?? '');
    $exempt = ($_POST['exempt'] ?? '0') === '1' ? '1' : '0';
    if (empty($pub)) {
        header('Content-Type: application/json'); http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing pubkey.']); exit;
    }
    $a_peers = wgx_get_config_array_dash('peer');
    $found   = false;
    foreach ($a_peers as &$peer) {
        if (($peer['publickey'] ?? '') === $pub) {
            $peer['wgx_quota_exempt'] = $exempt;
            $found = true;
            break;
        }
    }
    unset($peer);
    if (!$found) {
        header('Content-Type: application/json'); http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Peer not found.']); exit;
    }
    config_set_path('installedpackages/wireguard/peers/item', $a_peers);
    write_config("WG Suite: Updated quota exemption for peer");
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'exempt' => $exempt]); exit;
}

// === POST: Enhanced Telemetry Endpoint ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'get_telemetry') {
    if (!csrf_check(false)) {
        ob_end_clean(); header('Content-Type: application/json'); http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'CSRF validation failed.']); exit;
    }
    ob_start();
    try {
        $wg_bin = is_executable('/usr/local/bin/wg') ? '/usr/local/bin/wg' : '/usr/bin/wg';
        $telemetry = []; $endpoints = []; $endpoint_ports = [];

        if (!empty($wg_bin)) {
            // Single `wg show all dump` call replaces three separate exec() calls.
            // Peer line columns: iface pubkey preshared endpoint allowed-ips handshake rx tx keepalive
            $cache_file = '/tmp/wgx_telemetry_cache.json';
            $cache_life = 3;
            $dump_lines = [];

            if (file_exists($cache_file) && (time() - filemtime($cache_file)) < $cache_life) {
                $dump_lines = json_decode(file_get_contents($cache_file), true) ?? [];
            } else {
                exec(escapeshellarg($wg_bin) . ' show all dump 2>/dev/null', $dump_lines);
                file_put_contents($cache_file, json_encode($dump_lines));
            }

            foreach ($dump_lines as $line) {
                $parts = preg_split('/\s+/', trim($line));
                // Peer lines have 9 columns; interface lines have 5 — skip those
                if (count($parts) < 9) continue;
                $pub      = $parts[1];
                $endpoint = $parts[3];
                $hs       = (int)$parts[5];
                $rx       = (int)$parts[6];
                $tx       = (int)$parts[7];

                $telemetry[$pub] = ['rx' => $rx, 'tx' => $tx, 'hs' => $hs];

                if ($endpoint !== '(none)') {
                    $last_colon = strrpos($endpoint, ':');
                    if ($last_colon !== false) {
                        $endpoints[$pub]      = trim(substr($endpoint, 0, $last_colon), '[]');
                        $endpoint_ports[$pub] = substr($endpoint, $last_colon + 1);
                    } else {
                        $endpoints[$pub] = trim($endpoint, '[]');
                    }
                }
            }
        }

        // Load telemetry archive (24h history)
        $archive_file = '/var/db/wgx_telemetry_archive.json';
        $archive = file_exists($archive_file) ? json_decode(file_get_contents($archive_file), true) : [];
        if (!is_array($archive)) { $archive = []; }

        // ── Telemetry archive WRITER ────────────────────────────────────
        // The dashboard used to only READ this file, so history was always
        // empty and the 24h trend + sparklines had nothing to draw. Here we
        // record the current cumulative rx/tx for each peer into an hourly
        // bucket and prune anything older than 24h. Hourly bucketing keeps
        // the archive to <=24 points per peer.
        $now_ts       = time();
        $hour_bucket  = $now_ts - ($now_ts % 3600);   // round down to the hour
        $cutoff       = $now_ts - 86400;              // keep last 24h
        $archive_dirty = false;
        foreach ($telemetry as $tpub => $tvals) {
            if ($tpub === '') { continue; }
            if (!isset($archive[$tpub]) || !is_array($archive[$tpub])) {
                $archive[$tpub] = ['history' => []];
            }
            if (!isset($archive[$tpub]['history']) || !is_array($archive[$tpub]['history'])) {
                $archive[$tpub]['history'] = [];
            }
            // Overwrite the current hour bucket with the latest cumulative
            // counters. The trend/sparkline code diffs consecutive buckets
            // to derive per-hour throughput, so storing cumulative is correct.
            $archive[$tpub]['history'][(string)$hour_bucket] = [
                'rx' => (int)($tvals['rx'] ?? 0),
                'tx' => (int)($tvals['tx'] ?? 0),
            ];
            // Prune old buckets.
            foreach ($archive[$tpub]['history'] as $bts => $_bv) {
                if ((int)$bts < $cutoff) {
                    unset($archive[$tpub]['history'][$bts]);
                }
            }
            $archive_dirty = true;
        }
        // Drop archive entries for peers that no longer exist in telemetry
        // at all (deleted peers) once they age out completely.
        foreach ($archive as $apub => $adata) {
            if (empty($adata['history'])) { unset($archive[$apub]); $archive_dirty = true; }
        }
        if ($archive_dirty) {
            // Atomic write so a concurrent poll never reads a half-written file.
            $tmp = $archive_file . '.tmp';
            if (@file_put_contents($tmp, json_encode($archive), LOCK_EX) !== false) {
                @rename($tmp, $archive_file);
                @chmod($archive_file, 0600);
            }
        }

        // Load IP reputation / geolocation data
        $rep_file = '/var/db/wgx_ip_reputation.json';
        $rep_data = file_exists($rep_file) ? (json_decode(file_get_contents($rep_file), true) ?? []) : [];

        // Global settings for quota
        $wgx_settings  = config_get_path('installedpackages/wgexport/config/0', []);
        $global_quota  = max(1, (int)($wgx_settings['quota_limit_gb'] ?? 100));

        $a_peers = wgx_get_config_array_dash('peer');
        $payload_peers = [];
        $used_ips = 0; $tunnels = []; $online_count = 0; $idle_count = 0; $offline_count = 0;
        $total_rx = 0; $total_tx = 0;
        $now = time();

        // ── Per-tunnel subnet map ───────────────────────────────────
        // Multi-tier resolution: kernel → tunnel config → assigned OPT
        // interface → peer inference. Assigned tunnels — whose Interface
        // Addresses rows the native package leaves empty — resolve from
        // the live interface, exactly like the package itself does.
        //   name => ['net','mask','mask_long','cidr','capacity','used','source']
        $ip_capacity = 0;
        $tun_subnets = [];
        $cfg_ifaces  = config_get_path('interfaces', []);
        foreach (wgx_get_config_array_dash('tunnel') as $t) {
            if (!isset($t['name'])) { continue; }
            $t_name = trim($t['name']);
            $tunnels[] = $t_name;
            $hit = wgx_dash_tunnel_ipv4($t, $cfg_ifaces);
            if ($hit === null) {
                // Unresolved so far — the tier-4 pre-pass below may still
                // infer a subnet from this tunnel's peers.
                $tun_subnets[$t_name] = ['net' => null, 'mask' => null,
                    'mask_long' => null, 'cidr' => null, 'capacity' => 0,
                    'used' => 0, 'source' => 'unresolved'];
                continue;
            }
            $t_mask = $hit['mask'];
            if ($t_mask < 0 || $t_mask > 32) { $t_mask = 24; }
            $mask_long = ($t_mask === 0) ? 0 : ((-1 << (32 - $t_mask)) & 0xFFFFFFFF);
            $net_long  = ip2long($hit['ip']) & $mask_long;
            // Usable hosts = 2^(32-mask) - 2 (network + broadcast), minus the
            // tunnel's own gateway address. /31 and /32 carry no peers.
            $host_bits = 32 - $t_mask;
            $usable = $host_bits >= 2 ? ((1 << $host_bits) - 2) : 0;
            $usable = max(0, $usable - 1);
            $tun_subnets[$t_name] = [
                'net'       => $net_long,
                'mask'      => $t_mask,
                'mask_long' => $mask_long,
                'cidr'      => long2ip($net_long) . '/' . $t_mask,
                'capacity'  => $usable,
                'used'      => 0,
                'source'    => $hit['source'],
            ];
            $ip_capacity += $usable;
        }

        // Tier 4: for tunnels still unresolved, infer a /24 around the
        // first peer /32 address on that tunnel. Flagged as 'inferred' so
        // the UI marks the assumption instead of silently guessing.
        foreach ($tun_subnets as $sname => $s) {
            if ($s['net'] !== null) { continue; }
            foreach ($a_peers as $probe) {
                if (!is_array($probe) || trim($probe['tun'] ?? '') !== $sname) { continue; }
                $probe_ai   = isset($probe['allowedips']) && is_array($probe['allowedips']) ? $probe['allowedips'] : [];
                $probe_rows = $probe_ai['row'] ?? ($probe_ai['item'] ?? []);
                if (!is_array($probe_rows) || empty($probe_rows)) { continue; }
                $probe_rows = isset($probe_rows['address']) ? [$probe_rows] : $probe_rows;
                foreach ($probe_rows as $pr) {
                    if (is_array($pr) && !empty($pr['address']) && (int)($pr['mask'] ?? 0) === 32 &&
                        filter_var($pr['address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        $inf_mask_long = ((-1 << 8) & 0xFFFFFFFF);
                        $inf_net_long  = ip2long($pr['address']) & $inf_mask_long;
                        $tun_subnets[$sname] = [
                            'net'       => $inf_net_long,
                            'mask'      => 24,
                            'mask_long' => $inf_mask_long,
                            'cidr'      => long2ip($inf_net_long) . '/24',
                            'capacity'  => 253,
                            'used'      => 0,
                            'source'    => 'inferred',
                        ];
                        $ip_capacity += 253;
                        break 2;
                    }
                }
            }
        }
        $total_tunnels = count($tunnels);

        foreach ($a_peers as $p) {
            if (!is_array($p)) continue;
            $pub  = $p['publickey'] ?? '';
            $desc = $p['descr'] ?? 'Unknown';
            $tun  = $p['tun'] ?? 'Unknown';

            $rx = $telemetry[$pub]['rx'] ?? 0;
            $tx = $telemetry[$pub]['tx'] ?? 0;
            $hs = $telemetry[$pub]['hs'] ?? 0;
            $ep_ip   = $endpoints[$pub] ?? null;
            $ep_port = $endpoint_ports[$pub] ?? null;

            $total_rx += $rx;
            $total_tx += $tx;

            // Status classification
            $diff = $hs > 0 ? ($now - $hs) : PHP_INT_MAX;
            if ($hs > 0 && $diff < 180) $online_count++;
            elseif ($hs > 0 && $diff < 86400) $idle_count++;
            else $offline_count++;

            // Per-peer bandwidth history (from archive)
            $history = [];
            if (isset($archive[$pub]['history'])) {
                foreach ($archive[$pub]['history'] as $ts => $val) {
                    $history[$ts] = $val;
                }
            }

            // Allowed IPs — display every row, but count "used" only for
            // the peer's tunnel address. pfSense stores that address as a
            // /32 in Allowed IPs; split-tunnel LAN routes (192.168.1.0/24)
            // live in the same list and are routes, not addresses. A peer
            // counts at most ONCE, and only if its IPv4 address falls inside
            // its OWN tunnel's subnet (net-long mask compare).
            $assigned_ips_arr = [];
            $peer_tunnel_ip   = null;
            $allowedips = isset($p['allowedips']) && is_array($p['allowedips']) ? $p['allowedips'] : [];
            $raw_allowedips = $allowedips['row'] ?? ($allowedips['item'] ?? []);
            if (is_array($raw_allowedips) && !empty($raw_allowedips)) {
                $rows = isset($raw_allowedips['address']) ? [$raw_allowedips] : $raw_allowedips;
                $tun_key = trim($tun);
                if (!isset($tun_subnets[$tun_key])) {
                    foreach (array_keys($tun_subnets) as $tk) {
                        if (strcasecmp($tk, $tun_key) === 0) { $tun_key = $tk; break; }
                    }
                }
                $sub  = $tun_subnets[$tun_key] ?? null;
                foreach ($rows as $row) {
                    if (!is_array($row) || empty($row['address'])) { continue; }
                    $assigned_ips_arr[] = $row['address'];
                    if ($peer_tunnel_ip === null && $sub !== null && $sub['net'] !== null &&
                        filter_var($row['address'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) &&
                        ((ip2long($row['address']) & $sub['mask_long']) === $sub['net'])) {
                        $peer_tunnel_ip = $row['address'];
                    }
                }
                if ($peer_tunnel_ip !== null) {
                    $tun_subnets[$tun_key]['used']++;
                    $used_ips++;
                }
            }

            // Geo / Reputation lookup (keyed by public endpoint IP)
            $geo = null;
            if ($ep_ip && isset($rep_data[$ep_ip])) {
                $r = $rep_data[$ep_ip];
                $geo = [
                    'country'      => $r['country'] ?? '',
                    'country_code' => $r['country_code'] ?? '',
                    'city'         => $r['city'] ?? '',
                    'isp'          => $r['isp'] ?? '',
                    'org'          => $r['org'] ?? '',
                    'flags'        => $r['flags'] ?? [],
                    'lat'          => $r['lat'] ?? null,
                    'lon'          => $r['lon'] ?? null,
                ];
            }

            // Per-peer quota
            $peer_quota_gb = (int)($p['wgx_quota_limit_gb'] ?? 0);
            $effective_quota = $peer_quota_gb > 0 ? $peer_quota_gb : $global_quota;

            $payload_peers[] = [
                'pub'            => $pub,
                'name'           => $desc,
                'tun'            => $tun,
                'rx'             => $rx,
                'tx'             => $tx,
                'total'          => $rx + $tx,
                'handshake'      => $hs,
                'ip'             => $ep_ip,
                'ep_port'        => $ep_port,
                'assigned_ip'    => implode(', ', $assigned_ips_arr),
                'history'        => $history,
                'quota_exempt'   => ($p['wgx_quota_exempt'] ?? '0') === '1',
                'quota_gb'       => $effective_quota,
                'enabled'        => ($p['enabled'] ?? 'yes') === 'yes',
                'schedule'       => $p['wgx_schedule'] ?? 'always',
                'expire_time'    => !empty($p['expire_time']) ? (int)$p['expire_time'] : null,
                'geo'            => $geo,
                'offline_alert_hours' => (int)($p['wgx_offline_alert_hours'] ?? 0),
            ];
        }

        $available_ips = max(0, $ip_capacity - $used_ips);

        // Per-tunnel subnet utilisation breakdown
        $subnet_payload = [];
        foreach ($tun_subnets as $sname => $s) {
            $subnet_payload[] = [
                'tun'      => $sname,
                'cidr'     => $s['cidr'],
                'used'     => $s['used'],
                'capacity' => $s['capacity'],
                'pct'      => $s['capacity'] > 0 ? round(($s['used'] / $s['capacity']) * 100, 1) : 0,
                'source'   => $s['source'] ?? '',
            ];
        }

        // Top Talkers (24h) — ranked server-side from the telemetry archive.
        // Buckets hold cumulative rx/tx; diff consecutive buckets, reset-aware
        // (counter reset => take the new value as the delta).
        $talkers = [];
        foreach ($payload_peers as $pp) {
            $hist = $archive[$pp['pub']]['history'] ?? [];
            if (!is_array($hist) || count($hist) < 2) { continue; }
            ksort($hist, SORT_NUMERIC);
            $prev = null; $delta24 = 0;
            foreach ($hist as $bv) {
                $bytes = is_array($bv) ? ((int)($bv['rx'] ?? 0) + (int)($bv['tx'] ?? 0)) : (int)$bv;
                if ($prev !== null) {
                    $d = $bytes - $prev;
                    if ($d < 0) { $d = $bytes; }
                    $delta24 += $d;
                }
                $prev = $bytes;
            }
            if ($delta24 > 0) {
                $talkers[] = ['name' => $pp['name'], 'tun' => $pp['tun'], 'bytes' => $delta24];
            }
        }
        usort($talkers, function ($a, $b) { return $b['bytes'] <=> $a['bytes']; });
        $talkers = array_slice($talkers, 0, 5);

        // Country distribution from the geo cache already being collected
        $country_dist = [];
        foreach ($payload_peers as $pp) {
            if (!empty($pp['geo']['country_code'])) {
                $cc = $pp['geo']['country_code'];
                if (!isset($country_dist[$cc])) {
                    $country_dist[$cc] = ['code' => $cc,
                        'name' => ($pp['geo']['country'] !== '' ? $pp['geo']['country'] : $cc),
                        'count' => 0];
                }
                $country_dist[$cc]['count']++;
            }
        }
        $country_dist = array_values($country_dist);
        usort($country_dist, function ($a, $b) { return $b['count'] <=> $a['count']; });

        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode([
            'success'       => true,
            'peers'         => $payload_peers,
            'tunnels'       => $tunnels,
            'ip_used'       => $used_ips,
            'ip_free'       => $available_ips,
            'ip_capacity'   => $ip_capacity,
            'subnets'       => $subnet_payload,
            'top_talkers'   => $talkers,
            'countries'     => $country_dist,
            'total_rx'      => $total_rx,
            'total_tx'      => $total_tx,
            'online'        => $online_count,
            'idle'          => $idle_count,
            'offline'       => $offline_count,
            'server_time'   => microtime(true),
        ]);
        exit;

    } catch (\Throwable $e) {
        ob_end_clean();
        syslog(LOG_ERR, 'WG Suite dashboard error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'An internal error occurred. Check the system log for details.']); exit;
    }
}

// === Page Setup ===
$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("NOC Dashboard")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Dashboard"), true, "/wgx/vpn_wg_dashboard.php");
$tab_array[] = array(gettext("Export"), false, "/wgx/vpn_wg_export.php");
$tab_array[] = array(gettext("Setup"), false, "/wgx/vpn_wg_setup.php");
$tab_array[] = array(gettext("Audit"), false, "/wgx/vpn_wg_audit.php");
display_top_tabs($tab_array);
?>

<script src="/wg_chart.js"></script>

<style>
/* === NOC Dashboard Styles === */
:root { --noc-green: #27ae60; --noc-amber: #f39c12; --noc-red: #c0392b; --noc-blue: #2980b9; --noc-purple: #8e44ad; --noc-dark: #2c3e50; --noc-muted: #95a5a6; }

.noc-wrap { margin: 0; }

/* Summary Cards */
.noc-cards { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
.noc-card { flex: 1; min-width: 130px; background: rgba(128,128,128,0.04); border: 1px solid rgba(128,128,128,0.2); border-radius: 6px; padding: 14px 12px; text-align: center; position: relative; overflow: hidden; transition: box-shadow 0.2s; }
.noc-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.noc-card::before { content:''; position: absolute; top: 0; left: 0; right: 0; height: 3px; }
.noc-card.card-tunnels::before { background: var(--noc-blue); }
.noc-card.card-total::before  { background: var(--noc-dark); }
.noc-card.card-online::before { background: var(--noc-green); }
.noc-card.card-idle::before   { background: var(--noc-amber); }
.noc-card.card-offline::before{ background: var(--noc-red); }
.noc-card.card-rx::before     { background: var(--noc-green); }
.noc-card.card-tx::before     { background: var(--noc-blue); }
.noc-card-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.65; font-weight: 600; margin-bottom: 4px; }
.noc-card-value { font-size: 22px; font-weight: 700; line-height: 1.1; }
.noc-card-sub { font-size: 11px; opacity: 0.55; margin-top: 2px; }

/* Controls */
.noc-controls { background: rgba(128,128,128,0.06); padding: 14px; border-radius: 5px; margin-bottom: 18px; border: 1px solid rgba(128,128,128,0.2); }

/* Status indicators */
.noc-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }
.noc-dot-on  { background: var(--noc-green); box-shadow: 0 0 5px rgba(39,174,96,0.5); }
.noc-dot-idle{ background: var(--noc-amber); }
.noc-dot-off { background: var(--noc-red); }
.noc-dot-dis { background: #ccc; }

/* Speed badge */
.noc-speed { font-family: 'Courier New', monospace; font-size: 13px; font-weight: 700; padding: 3px 8px; border-radius: 3px; display: inline-block; min-width: 90px; text-align: center; }
.noc-speed-high { background: rgba(192,57,43,0.15); color: var(--noc-red); }
.noc-speed-med  { background: rgba(243,156,18,0.15); color: #e67e22; }
.noc-speed-low  { background: rgba(39,174,96,0.15); color: var(--noc-green); }
.noc-speed-idle { background: rgba(0,0,0,0.04); color: #aaa; }

/* Anomaly & reputation badges */
.noc-badge { font-size: 10px; padding: 2px 6px; border-radius: 3px; font-weight: 600; display: inline-block; margin: 1px 2px; white-space: nowrap; }
.noc-badge-tor     { background: #e74c3c; color: #fff; }
.noc-badge-proxy   { background: #e67e22; color: #fff; }
.noc-badge-hosting { background: #9b59b6; color: #fff; }
.noc-badge-spike   { background: #3498db; color: #fff; }
.noc-badge-newep   { background: #1abc9c; color: #fff; }
.noc-badge-expired { background: #e74c3c; color: #fff; }
.noc-badge-sched   { background: #34495e; color: #fff; }
.noc-badge-disabled{ background: #bdc3c7; color: #555; }

/* Geo display */
.noc-geo { font-size: 11px; opacity: 0.75; }
.noc-geo-flag { font-size: 16px; vertical-align: middle; margin-right: 3px; }
.noc-geo-isp { font-size: 10px; opacity: 0.55; display: block; margin-top: 1px; }

/* Quota bar */
.noc-quota { height: 16px; margin: 0; border-radius: 3px; overflow: hidden; }
.noc-quota .progress-bar { line-height: 16px; font-size: 10px; font-weight: 600; }

/* Sparkline */
.noc-sparkline { vertical-align: middle; }

/* Table enhancements */
#peerTable th { border-bottom: 2px solid rgba(128,128,128,0.3); white-space: nowrap; }
#peerTable td { vertical-align: middle; }
#peerTable tbody tr.noc-peer-row { cursor: pointer; transition: background 0.15s; }
#peerTable tbody tr.noc-peer-row:hover { background: rgba(41,128,185,0.06); }
.quota-exceeded { background-color: rgba(192,57,43,0.08) !important; }

/* Detail drawer */
.noc-drawer { display: none; background: rgba(128,128,128,0.06); border-top: 1px dashed rgba(128,128,128,0.3); }
.noc-drawer.open { display: table-row; }
.noc-drawer-inner { padding: 16px 20px; }
.noc-drawer-section { margin-bottom: 14px; }
.noc-drawer-section h6 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.65; margin: 0 0 8px; font-weight: 700; }
.noc-drawer-stats { display: flex; gap: 20px; flex-wrap: wrap; }
.noc-drawer-stat { text-align: center; }
.noc-drawer-stat-val { font-size: 18px; font-weight: 700; }
.noc-drawer-stat-label { font-size: 10px; opacity: 0.55; text-transform: uppercase; }
.noc-drawer-chart-wrap { height: 140px; position: relative; width: 100%; margin-top: 8px; }

/* Handshake age */
.noc-hs-age { font-size: 11px; white-space: nowrap; }
.noc-hs-time { font-size: 10px; opacity: 0.55; display: block; }

/* Ratio bar */
.noc-ratio { display: flex; height: 6px; border-radius: 3px; overflow: hidden; width: 80px; margin-top: 3px; }
.noc-ratio-rx { background: var(--noc-green); }
.noc-ratio-tx { background: var(--noc-blue); }

/* Subnet utilisation table */
.noc-sub-bar { height: 14px; border-radius: 3px; background: rgba(128,128,128,0.12); overflow: hidden; position: relative; }
.noc-sub-fill { height: 100%; transition: width 0.4s; }
.noc-sub-fill.ok   { background: var(--noc-green); }
.noc-sub-fill.warn { background: var(--noc-amber); }
.noc-sub-fill.crit { background: var(--noc-red); }
.noc-sub-pct { font-size: 10px; font-weight: 700; position: absolute; right: 5px; top: 0; line-height: 14px; }

/* Top talkers */
.noc-talkers { padding-left: 20px; margin: 0; }
.noc-talkers li { margin-bottom: 6px; font-size: 12px; }
.noc-talkers .noc-talker-bytes { float: right; font-weight: 700; font-family: 'Courier New', monospace; }
.noc-talkers .noc-talker-tun { display: block; font-size: 10px; opacity: 0.55; }

/* Country chips */
.noc-cchip { display: inline-block; padding: 3px 9px; margin: 2px 3px 2px 0; border-radius: 12px; background: rgba(41,128,185,0.12); border: 1px solid rgba(41,128,185,0.3); font-size: 12px; }
.noc-cchip .noc-cchip-n { font-weight: 700; margin-left: 4px; }

@media (max-width: 767px) {
    .noc-cards { flex-direction: row; flex-wrap: wrap; }
    .noc-card { min-width: calc(50% - 10px); flex: 1 1 calc(50% - 10px); }
    .noc-card-value { font-size: 18px; }
    #peerTable thead { display: none; }
    #peerTable tr { display: block; border-bottom: 2px solid rgba(128,128,128,0.2); padding: 6px 0; }
    #peerTable td { display: block; text-align: left !important; padding: 3px 8px; border: none; }
    .noc-controls .col-sm-2, .noc-controls .col-sm-3, .noc-controls .col-sm-4 { width: 100% !important; margin-bottom: 6px; }
    .noc-drawer-stats { gap: 10px; }
    .noc-speed { min-width: 70px; font-size: 11px; }
    .table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    .panel-body { padding: 8px; }
}
</style>

<div class="noc-wrap">
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><i class="fa fa-dashboard"></i> Network Operations Center</h2></div>
<div class="panel-body">

    <!-- Summary Cards -->
    <div class="noc-cards" id="nocCards">
        <div class="noc-card card-tunnels">
            <div class="noc-card-label"><i class="fa fa-server"></i> Tunnels</div>
            <div class="noc-card-value" id="cardTunnels">—</div>
        </div>
        <div class="noc-card card-total">
            <div class="noc-card-label"><i class="fa fa-users"></i> Total Peers</div>
            <div class="noc-card-value" id="cardTotal">—</div>
        </div>
        <div class="noc-card card-online">
            <div class="noc-card-label"><i class="fa fa-check-circle"></i> Online</div>
            <div class="noc-card-value" id="cardOnline" style="color:var(--noc-green);">—</div>
        </div>
        <div class="noc-card card-idle">
            <div class="noc-card-label"><i class="fa fa-clock-o"></i> Idle</div>
            <div class="noc-card-value" id="cardIdle" style="color:var(--noc-amber);">—</div>
        </div>
        <div class="noc-card card-offline">
            <div class="noc-card-label"><i class="fa fa-times-circle"></i> Offline</div>
            <div class="noc-card-value" id="cardOffline" style="color:var(--noc-red);">—</div>
        </div>
        <div class="noc-card card-rx">
            <div class="noc-card-label"><i class="fa fa-arrow-down"></i> Total Rx</div>
            <div class="noc-card-value" id="cardRx" style="font-size:16px;">—</div>
        </div>
        <div class="noc-card card-tx">
            <div class="noc-card-label"><i class="fa fa-arrow-up"></i> Total Tx</div>
            <div class="noc-card-value" id="cardTx" style="font-size:16px;">—</div>
        </div>
    </div>

    <!-- Controls -->
    <div class="noc-controls">
        <div class="row">
            <div class="col-sm-2">
                <label><i class="fa fa-server"></i> Tunnel</label>
                <select id="filterTun" class="form-control input-sm" onchange="processData()"><option value="ALL">All Tunnels</option></select>
            </div>
            <div class="col-sm-2">
                <label><i class="fa fa-filter"></i> Show</label>
                <select id="filterTop" class="form-control input-sm" onchange="processData()">
                    <option value="10">Top 10</option>
                    <option value="25">Top 25</option>
                    <option value="50">Top 50</option>
                    <option value="9999" selected>All Peers</option>
                </select>
            </div>
            <div class="col-sm-2">
                <label><i class="fa fa-eye"></i> Status</label>
                <select id="filterStatus" class="form-control input-sm" onchange="processData()">
                    <option value="ALL">All</option>
                    <option value="online">Online</option>
                    <option value="idle">Idle</option>
                    <option value="offline">Offline</option>
                </select>
            </div>
            <div class="col-sm-3">
                <label><i class="fa fa-search"></i> Search</label>
                <input type="text" id="filterSearch" class="form-control input-sm" placeholder="Name, IP, ISP, country..." oninput="processData()">
                <button class="btn btn-default btn-sm" id="btnCompactToggle" onclick="toggleCompactView()" title="Toggle compact view" style="margin-left:6px;"><i class="fa fa-compress"></i></button>
            </div>
            <div class="col-sm-1">
                <label><i class="fa fa-tachometer"></i> Quota</label>
                <input type="number" id="quotaLimit" class="form-control input-sm" value="100" oninput="processData()">
            </div>
            <div class="col-sm-2 text-right" style="padding-top:22px;">
                <label style="font-size:12px;">
                <input type="checkbox" id="liveToggle" checked onchange="togglePolling()"> <i class="fa fa-bolt"></i> Live (7s)
                &nbsp;<span id="lastUpdatedStamp" class="text-muted" style="font-size:11px;"></span>
                </label>
            </div>
        </div>
    </div>

    <!-- Charts Row 1 -->
    <div class="row" style="margin-bottom: 24px;">
        <div class="col-sm-8">
            <h5><i class="fa fa-bar-chart"></i> Live Bandwidth</h5>
            <div style="height: 230px; position: relative;"><canvas id="bwChart"></canvas></div>
        </div>
        <div class="col-sm-4">
            <h5><i class="fa fa-pie-chart"></i> Subnet Usage <span id="pieScope" class="text-muted" style="font-size:11px;font-weight:normal;"></span></h5>
            <div style="height: 230px; position: relative;">
                <canvas id="ipPieChart"></canvas>
                <div id="ipPieEmpty" style="display:none; position:absolute; inset:0; align-items:center; justify-content:center; text-align:center; color:#7f8c8d; font-size:12px;">
                    <div style="margin:auto;"><i class="fa fa-info-circle"></i><br>No tunnel subnets detected yet.</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row 2 -->
    <div class="row" style="margin-bottom: 24px;">
        <div class="col-sm-6">
            <h5><i class="fa fa-database"></i> Total Data per Peer</h5>
            <div style="height: 200px; position: relative;"><canvas id="totalDataChart"></canvas></div>
        </div>
        <div class="col-sm-6">
            <h5><i class="fa fa-line-chart"></i> 24h Aggregate Trend</h5>
            <div style="height: 200px; position: relative;">
                <canvas id="trendChart"></canvas>
                <div id="trendEmpty" style="display:none; position:absolute; inset:0; align-items:center; justify-content:center; text-align:center; color:#7f8c8d; font-size:12px;">
                    <div style="margin:auto;"><i class="fa fa-clock-o"></i><br>Collecting data… the trend needs at least two hourly samples.<br><span style="font-size:11px;opacity:0.8;">Leave the dashboard open; points appear as traffic flows.</span></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts Row 3: Subnet Utilisation / Top Talkers / Countries -->
    <div class="row" style="margin-bottom: 10px;">
        <div class="col-sm-5">
            <h5><i class="fa fa-sitemap"></i> Subnet Utilisation by Tunnel</h5>
            <table class="table table-condensed" id="subnetTable" style="margin-bottom:6px;">
                <thead><tr><th>Tunnel</th><th>Subnet</th><th style="width:45%;">Utilisation</th><th class="text-right">Used / Cap</th></tr></thead>
                <tbody id="subnetTbody"><tr><td colspan="4" class="text-muted">Loading…</td></tr></tbody>
            </table>
        </div>
        <div class="col-sm-4">
            <h5><i class="fa fa-trophy"></i> Top Talkers (24h)</h5>
            <ol id="topTalkersList" class="noc-talkers"><li class="text-muted" style="list-style:none;">Collecting data…</li></ol>
        </div>
        <div class="col-sm-3">
            <h5><i class="fa fa-globe"></i> Peer Countries</h5>
            <div id="countryChips"><span class="text-muted" style="font-size:12px;">No geo data yet.</span></div>
        </div>
    </div>

    </div> </div>
    </div> <div class="panel panel-default">
    <div class="panel-heading">
    <h2 class="panel-title"><i class="fa fa-users"></i> Peer Intelligence <span id="peerCount" style="font-size:12px; margin-left:8px; opacity:0.8;"></span></h2>
    </div>
    <div class="panel-body">
    <div class="table-responsive">
    <table class="table table-striped table-hover" id="peerTable">
    <thead>
    <tr>
    <th>Peer</th>
    <th>Location</th>
    <th>IP / Endpoint</th>
    <th>Last Handshake</th>
    <th>24h Trend</th>
    <th>Speed</th>
    <th>Data (Rx/Tx)</th>
    <th>Quota</th>
    <th style="width:3%;"></th>
    </tr>
    </thead>
            <tbody id="peerTbody"></tbody>
        </table>
    </div>

    </div>
    </div>

    </div>

    <script>
    // === State ===
let bwChartInst = null, pieChartInst = null, trendChartInst = null, totalDataChartInst = null;
let pollInterval = null, globalPeerData = [], previousPeerState = {};
let lastProcessedServerTime = 0, serverTime = 0, seenEndpoints = {};
const POLL_RATE_SEC = 7;

// === Utilities ===
function getCsrf() {
    if (typeof csrfMagicToken !== 'undefined') return csrfMagicToken;
    const el = document.querySelector("input[name='__csrf_magic']");
    return el ? el.value : '';
}

function fmtBytes(bytes, dec) {
    if (!+bytes) return '0 B';
    dec = dec === undefined ? 2 : dec;
    const k = 1024, s = ['B','KB','MB','GB','TB','PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dec)) + ' ' + s[i];
}

function fmtAge(ts) {
    if (!ts || ts <= 0) return { text: 'Never', cls: 'text-muted' };
    const d = serverTime - ts;
    if (d < 0) return { text: 'Just now', cls: 'text-success' };
    if (d < 60) return { text: d + 's ago', cls: 'text-success' };
    if (d < 3600) return { text: Math.floor(d/60) + 'm ago', cls: d < 180 ? 'text-success' : 'text-warning' };
    if (d < 86400) return { text: Math.floor(d/3600) + 'h ago', cls: 'text-warning' };
    return { text: Math.floor(d/86400) + 'd ago', cls: 'text-danger' };
}

function countryFlag(cc) {
    if (!cc || cc.length !== 2) return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// Last telemetry snapshot, kept for filter-aware pie rendering
var lastIpStats = null;   // { used, free, capacity }
var lastSubnets = [];     // per-tunnel breakdown from the backend

// Precise percentage: never rounds nonzero use down to 0%, never rounds a
// not-full pool up to 100%. 2/506 -> '0.4%', 504/506 -> '99.6%'.
function fmtPctPrecise(v, capacity) {
    if (!capacity || capacity <= 0) return '0%';
    if (v <= 0) return '0%';
    if (v >= capacity) return '100%';
    const p = (v / capacity) * 100;
    if (p < 0.1) return '<0.1%';
    if (p > 99.9) return '>99.9%';
    const r = Math.round(p * 10) / 10;
    if (r <= 0) return '<0.1%';
    if (r >= 100) return '>99.9%';
    return r + '%';
}

function escH(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function peerStatus(p) {
    if (!p.enabled) return { label: 'Disabled', cls: 'noc-dot-dis', key: 'disabled' };
    const d = p.handshake > 0 ? serverTime - p.handshake : Infinity;
    if (d < 180) return { label: 'Online', cls: 'noc-dot-on', key: 'online' };
    if (d < 86400) return { label: 'Idle', cls: 'noc-dot-idle', key: 'idle' };
    return { label: 'Offline', cls: 'noc-dot-off', key: 'offline' };
}

// SVG sparkline from hourly history
function sparkSVG(history, w, h) {
    w = w || 110; h = h || 28;
    const entries = Object.entries(history || {}).sort((a,b) => a[0] - b[0]);
    if (entries.length < 2) return '<span class="text-muted" style="font-size:10px;">—</span>';
    const vals = entries.map(([,v]) => (v && typeof v === 'object') ? ((v.rx||0)+(v.tx||0)) : (v||0));
    const mx = Math.max(...vals) || 1;
    let prev = vals[0]; const deltas = vals.map((v,i) => { if(i===0) return 0; let d=v-prev; if(d<0) d=v; prev=v; return d; });
    const mxD = Math.max(...deltas) || 1;
    const pts = deltas.map((v,i) => ((i/(deltas.length-1))*w).toFixed(1)+','+(h-2-(v/mxD)*(h-4)).toFixed(1)).join(' ');
    return `<svg class="noc-sparkline" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline points="${pts}" fill="none" stroke="#2980b9" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
}

function scheduleLabel(s) {
    const m = { always:'Always', weekdays:'Mon–Fri', weekends:'Sat–Sun', business_hours:'9–5 M–F', business:'9–5 M–F', nights:'Nights', weekend:'Sat–Sun' };
    return m[s] || s;
}

// === Fetch ===
function fetchTelemetry() {
    const body = new URLSearchParams({ action: 'get_telemetry', __csrf_magic: getCsrf() });
    fetch('/wgx/vpn_wg_dashboard.php', { method: 'POST', body })
        .then(r => r.json())
        .then(data => {
            if (!data.success) return;
            document.getElementById('lastUpdatedStamp').textContent = 'Updated ' + new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
            const t = data.server_time;
            if (data.peers) checkOfflineAlerts(data.peers);
            if (t <= lastProcessedServerTime) return;
            lastProcessedServerTime = t;
            serverTime = Math.floor(t);

            // Populate tunnel filter once
            const sel = document.getElementById('filterTun');
            if (sel.options.length <= 1 && data.tunnels.length > 0)
                data.tunnels.forEach(tn => sel.add(new Option(tn, tn)));

            // Compute live speed via EMA
            data.peers.forEach(p => {
                p.liveSpeedBps = 0; p.deltaRx = 0; p.deltaTx = 0;
                const prev = previousPeerState[p.pub];
                if (prev) {
                    const dRx = Math.max(0, p.rx - prev.rx);
                    const dTx = Math.max(0, p.tx - prev.tx);
                    const dB  = dRx + dTx;
                    const dT  = t - prev.time;
                    if (dT > 2) {
                        p.deltaRx = dRx; p.deltaTx = dTx;
                        p.liveSpeedBps = dB > 512 ? (dB/dT)*0.7 + prev.ema*0.3 : prev.ema*0.3;
                    } else {
                        p.liveSpeedBps = prev.ema; p.deltaRx = prev.deltaRx||0; p.deltaTx = prev.deltaTx||0;
                    }
                }
                // Track new endpoints
                if (p.ip && !seenEndpoints[p.pub]) seenEndpoints[p.pub] = {};
                if (p.ip) { p._newEp = !seenEndpoints[p.pub][p.ip]; seenEndpoints[p.pub][p.ip] = true; }
                previousPeerState[p.pub] = { rx:p.rx, tx:p.tx, time:t, ema:p.liveSpeedBps||0, deltaRx:p.deltaRx, deltaTx:p.deltaTx };
            });

            globalPeerData = data.peers;

            // Summary cards
            document.getElementById('cardTunnels').textContent = data.tunnels.length;
            document.getElementById('cardTotal').textContent   = data.peers.length;
            document.getElementById('cardOnline').textContent   = data.online;
            document.getElementById('cardIdle').textContent     = data.idle;
            document.getElementById('cardOffline').textContent  = data.offline;
            document.getElementById('cardRx').textContent       = fmtBytes(data.total_rx, 1);
            document.getElementById('cardTx').textContent       = fmtBytes(data.total_tx, 1);

            processData();
            lastIpStats = { used: data.ip_used, free: data.ip_free, capacity: data.ip_capacity };
            lastSubnets = data.subnets || [];
            updatePieForFilter();
            renderSubnetTable(data.subnets);
            renderTopTalkers(data.top_talkers);
            renderCountryChips(data.countries);
        });
}

// === Filtering & Processing ===
function processData() {
    const search = document.getElementById('filterSearch').value.toLowerCase();
    const topN   = parseInt(document.getElementById('filterTop').value, 10);
    const selTun = document.getElementById('filterTun').value;
    const selSt  = document.getElementById('filterStatus').value;
    const qBytes = parseFloat(document.getElementById('quotaLimit').value || 100) * 1073741824;

    let filtered = globalPeerData.filter(p => {
        const st = peerStatus(p).key;
        if (selSt !== 'ALL' && st !== selSt) return false;
        if (selTun !== 'ALL' && p.tun !== selTun) return false;
        if (search) {
            const hay = (p.name + ' ' + (p.ip||'') + ' ' + (p.assigned_ip||'') + ' ' + (p.geo?.country||'') + ' ' + (p.geo?.city||'') + ' ' + (p.geo?.isp||'')).toLowerCase();
            if (!hay.includes(search)) return false;
        }
        return true;
    });

    filtered.sort((a,b) => b.total - a.total);
    const chartPeers = filtered.slice(0, topN);

    document.getElementById('peerCount').textContent = '(' + filtered.length + ' peers)';

    updateBarChart(chartPeers);
    updateTotalDataChart(chartPeers);
    updateTable(filtered, qBytes);
    updateTrendChart(chartPeers);
    updatePieForFilter();
}

// === Table Renderer ===
function updateTable(peers, qBytes) {
    const tbody = document.getElementById('peerTbody');
    // Preserve open drawers
    const openSet = new Set();
    tbody.querySelectorAll('.noc-drawer.open').forEach(el => openSet.add(el.dataset.pub));
    tbody.innerHTML = '';

    peers.forEach(p => {
        const st = peerStatus(p);
        const age = fmtAge(p.handshake);
        const mbps = (p.liveSpeedBps * 8) / 1e6;
        const pct = p.quota_exempt ? 0 : (p.total / qBytes) * 100;
        const ratio = p.total > 0 ? (p.rx / p.total * 100) : 50;

        // === Main row ===
        const tr = document.createElement('tr');
        tr.className = 'noc-peer-row';
        if (!p.quota_exempt && pct > 90) tr.classList.add('quota-exceeded');
        tr.onclick = () => {
            const drawer = document.getElementById('drawer-' + CSS.escape(p.pub));
            if (drawer) { drawer.classList.toggle('open'); if(drawer.classList.contains('open')) renderDrawerChart(p); }
        };

        // Peer name + Tunnel + Status + anomaly badges
        let nameHtml = `<div style="display:flex; align-items:center;"><span class="noc-dot ${st.cls}" title="${st.label}"></span> <strong>${escH(p.name)}</strong></div>`;
        nameHtml += `<div class="text-muted" style="font-size:11px;margin-top:2px;margin-bottom:2px;"><i class="fa fa-server" style="font-size:9px;"></i> ${escH(p.tun)}</div>`;

        let badges = '';
    if (p.geo?.flags) {
        if (p.geo.flags.includes('tor'))     badges += '<span class="noc-badge noc-badge-tor"><i class="fa fa-eye-slash"></i> TOR</span>';
    if (p.geo.flags.includes('proxy'))   badges += '<span class="noc-badge noc-badge-proxy"><i class="fa fa-shield"></i> PROXY</span>';
    if (p.geo.flags.includes('hosting')) badges += '<span class="noc-badge noc-badge-hosting"><i class="fa fa-cloud"></i> DC</span>';
    }
    if (p._newEp && p.ip) badges += '<span class="noc-badge noc-badge-newep"><i class="fa fa-bolt"></i> NEW EP</span>';
    if (mbps > 50) badges += '<span class="noc-badge noc-badge-spike"><i class="fa fa-arrow-up"></i> SPIKE</span>';
    if (!p.enabled) badges += '<span class="noc-badge noc-badge-disabled">DISABLED</span>';
    if (p.expire_time && p.expire_time < serverTime) badges += '<span class="noc-badge noc-badge-expired">EXPIRED</span>';
    if (p.schedule && p.schedule !== 'always') badges += `<span class="noc-badge noc-badge-sched"><i class="fa fa-calendar"></i> ${scheduleLabel(p.schedule)}</span>`;
    if (badges) nameHtml += '<div style="margin-top:3px;">' + badges + '</div>';

    // Location / Geo
    let geoHtml = '<span class="text-muted">—</span>';
        if (p.geo && p.geo.country_code) {
            geoHtml = `<span class="noc-geo"><span class="noc-geo-flag">${countryFlag(p.geo.country_code)}</span>${escH(p.geo.city || p.geo.country)}`;
            if (p.geo.isp) geoHtml += `<span class="noc-geo-isp">${escH(p.geo.isp)}</span>`;
            geoHtml += '</span>';
        }

        // IPs
        let ipHtml = `<div>${escH(p.assigned_ip || '—')}</div>`;
        if (p.ip) ipHtml += `<div class="text-muted" style="font-size:10px;">${escH(p.ip)}${p.ep_port ? ':'+escH(p.ep_port) : ''}</div>`;

        // Handshake age
        let hsHtml = `<span class="noc-hs-age ${age.cls}">${age.text}</span>`;
        if (p.handshake > 0) {
            const d = new Date(p.handshake * 1000);
            hsHtml += `<span class="noc-hs-time">${d.toLocaleDateString()} ${d.toLocaleTimeString()}</span>`;
        }

        // Speed
        let speedCls = 'noc-speed-idle';
    if (mbps > 20) speedCls = 'noc-speed-high';
    else if (mbps > 3) speedCls = 'noc-speed-med';
    else if (mbps > 0.01) speedCls = 'noc-speed-low';
    let speedHtml = `<span class="noc-speed ${speedCls}">${mbps < 0.01 && mbps > 0 ? '< 0.01' : mbps.toFixed(2)} Mbps</span>`;

        // Data + ratio
        let dataHtml = `<div>${fmtBytes(p.total)}</div>`;
        dataHtml += `<div class="text-muted" style="font-size:10px;"><i class="fa fa-arrow-down" style="color:var(--noc-green);"></i> ${fmtBytes(p.rx,1)} <i class="fa fa-arrow-up" style="color:var(--noc-blue);"></i> ${fmtBytes(p.tx,1)}</div>`;
        dataHtml += `<div class="noc-ratio"><div class="noc-ratio-rx" style="width:${ratio}%;"></div><div class="noc-ratio-tx" style="width:${100-ratio}%;"></div></div>`;

        // Quota
        let qHtml;
        if (p.quota_exempt) {
            qHtml = '<span class="label label-default" style="font-size:10px;padding:3px 6px;"><i class="fa fa-ban"></i> Exempt</span>';
        } else {
            const qC = pct > 90 ? 'progress-bar-danger' : pct > 75 ? 'progress-bar-warning' : 'progress-bar-success';
    qHtml = `<div class="progress noc-quota"><div class="progress-bar ${qC}" style="width:${Math.min(pct,100)}%;">${pct.toFixed(1)}%</div></div>`;
        }

        // Exempt toggle
        const eBtn = `<button class="btn btn-xs ${p.quota_exempt?'btn-warning':'btn-default'}" title="${p.quota_exempt?'Remove exemption':'Exempt from quota'}" onclick="event.stopPropagation();toggleQuotaExempt(this,'${escH(p.pub)}','${p.quota_exempt?'0':'1'}')"><i class="fa ${p.quota_exempt?'fa-check-circle':'fa-ban'}"></i></button>`;

        tr.innerHTML = `
        <td>${nameHtml}</td>
        <td>${geoHtml}</td>
        <td>${ipHtml}</td>
        <td>${hsHtml}</td>
        <td>${sparkSVG(p.history)}</td>
        <td>${speedHtml}</td>
        <td>${dataHtml}</td>
        <td>${qHtml}</td>
        <td>${eBtn}</td>
        `;
        tbody.appendChild(tr);

        // === Detail drawer row ===
        const drawerTr = document.createElement('tr');
        drawerTr.className = 'noc-drawer' + (openSet.has(p.pub) ? ' open' : '');
        drawerTr.id = 'drawer-' + p.pub;
        drawerTr.dataset.pub = p.pub;
        drawerTr.innerHTML = `<td colspan="9"><div class="noc-drawer-inner">
            <div class="row">
                <div class="col-sm-3">
                    <div class="noc-drawer-section">
                        <h6>Connection Details</h6>
                        <div class="noc-drawer-stats">
                            <div class="noc-drawer-stat"><div class="noc-drawer-stat-val">${fmtBytes(p.rx,1)}</div><div class="noc-drawer-stat-label">Download</div></div>
                            <div class="noc-drawer-stat"><div class="noc-drawer-stat-val">${fmtBytes(p.tx,1)}</div><div class="noc-drawer-stat-label">Upload</div></div>
                        </div>
                        <div style="margin-top:10px;font-size:11px;">
                            <div><strong>Assigned IP:</strong> ${escH(p.assigned_ip||'—')}</div>
                            <div><strong>Endpoint:</strong> ${p.ip ? escH(p.ip)+':'+(p.ep_port||'?') : 'Unknown'}</div>
                            <div><strong>Tunnel:</strong> ${escH(p.tun)}</div>
                            <div><strong>Status:</strong> ${p.enabled ? 'Enabled' : 'Disabled'}</div>
                            <div><strong>Schedule:</strong> ${scheduleLabel(p.schedule)}</div>
                            <div><strong>Quota:</strong> ${p.quota_exempt ? 'Exempt' : (p.quota_gb + ' GB')}</div>
                            ${p.expire_time ? '<div><strong>Expires:</strong> '+ new Date(p.expire_time*1000).toLocaleString()+'</div>' : ''}
                        </div>
                    </div>
                </div>
                <div class="col-sm-3">
                    <div class="noc-drawer-section">
                        <h6>Geolocation & Reputation</h6>
                        ${p.geo ? `
                            <div style="font-size:24px;margin-bottom:4px;">${countryFlag(p.geo.country_code)}</div>
                            <div style="font-size:12px;"><strong>${escH(p.geo.city||'')}</strong>${p.geo.city&&p.geo.country?', ':''}${escH(p.geo.country||'')}</div>
                            <div class="text-muted" style="font-size:11px;">ISP: ${escH(p.geo.isp||'—')}</div>
                            <div class="text-muted" style="font-size:11px;">Org: ${escH(p.geo.org||'—')}</div>
                            ${p.geo.flags&&p.geo.flags.length ? '<div style="margin-top:6px;">'+p.geo.flags.map(f=>'<span class="noc-badge noc-badge-'+f+'">'+f.toUpperCase()+'</span>').join(' ')+'</div>' : '<div style="margin-top:6px;font-size:11px;color:var(--noc-green);"><i class="fa fa-check"></i> Clean</div>'}
                        ` : '<span class="text-muted" style="font-size:11px;">No geo data — enable IP reputation in Global Settings</span>'}
                    </div>
                </div>
                <div class="col-sm-6">
                    <div class="noc-drawer-section">
                        <h6>24-Hour Bandwidth (This Peer)</h6>
                        <div class="noc-drawer-chart-wrap"><canvas id="drawerChart-${CSS.escape(p.pub)}"></canvas></div>
                    </div>
                </div>
            </div>
        </div></td>`;
        tbody.appendChild(drawerTr);

        if (openSet.has(p.pub)) renderDrawerChart(p);
    });
}

// === Per-Peer Drawer Chart ===
const drawerCharts = {};
function renderDrawerChart(p) {
    const canvasId = 'drawerChart-' + CSS.escape(p.pub);
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const entries = Object.entries(p.history || {}).sort((a,b) => a[0]-b[0]);
    if (entries.length < 2) return;

    let prevRx = 0, prevTx = 0;
    const labels = [], rxD = [], txD = [];
    entries.forEach(([ts, v], i) => {
        const rx = v?.rx || 0, tx = v?.tx || 0;
        const d = new Date(ts * 1000);
        labels.push(d.getHours() + ':00');
        if (i === 0) { rxD.push(0); txD.push(0); }
        else {
            let dRx = rx - prevRx; if (dRx < 0) dRx = rx;
            let dTx = tx - prevTx; if (dTx < 0) dTx = tx;
            rxD.push(dRx / 1048576);
            txD.push(dTx / 1048576);
        }
        prevRx = rx; prevTx = tx;
    });

    if (drawerCharts[p.pub]) { drawerCharts[p.pub].destroy(); delete drawerCharts[p.pub]; }
    drawerCharts[p.pub] = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: { labels, datasets: [
            { label: 'Rx (MB)', data: rxD, backgroundColor: 'rgba(39,174,96,0.6)' },
            { label: 'Tx (MB)', data: txD, backgroundColor: 'rgba(41,128,185,0.6)' }
        ]},
        options: { maintainAspectRatio: false, responsive: true, animation: { duration: 300 },
            scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { callback: v => v.toFixed(0)+' MB' } } },
            plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } } }
        }
    });
}

// === Charts (existing, refined) ===
function updateBarChart(peers) {
    const labels=[], rx=[], tx=[], rxC=[], txC=[];
    peers.forEach(p => {
        labels.push(p.name);
        const mbps = (p.liveSpeedBps*8)/1e6;
        rx.push(+(mbps*0.6).toFixed(3));
        tx.push(+(mbps*0.4).toFixed(3));
        const d = p.handshake > 0 ? serverTime - p.handshake : Infinity;
        if (d < 180)       { rxC.push('rgba(39,174,96,0.8)');  txC.push('rgba(39,174,96,0.4)'); }
        else if (d < 86400){ rxC.push('rgba(243,156,18,0.8)'); txC.push('rgba(243,156,18,0.4)'); }
        else               { rxC.push('rgba(192,57,43,0.8)');  txC.push('rgba(192,57,43,0.4)'); }
    });
    if (!bwChartInst) {
        const ctx = document.getElementById('bwChart').getContext('2d');
        bwChartInst = new Chart(ctx, { type:'bar', data:{labels,datasets:[{label:'Rx',data:rx,backgroundColor:rxC},{label:'Tx',data:tx,backgroundColor:txC}]},
            options:{maintainAspectRatio:false,responsive:true,animation:{duration:400},scales:{y:{beginAtZero:true,ticks:{callback:v=>v.toFixed(2)+' Mbps'},title:{display:true,text:'Live Speed'}}},plugins:{tooltip:{callbacks:{label:c=>c.dataset.label+': '+c.raw.toFixed(3)+' Mbps'}}}}});
    } else { bwChartInst.data.labels=labels; bwChartInst.data.datasets[0].data=rx; bwChartInst.data.datasets[0].backgroundColor=rxC; bwChartInst.data.datasets[1].data=tx; bwChartInst.data.datasets[1].backgroundColor=txC; bwChartInst.update(); }
}

function updateTotalDataChart(peers) {
    const labels=[],rxD=[],txD=[],rxC=[],txC=[];
    peers.forEach(p => {
        labels.push(p.name);
        rxD.push(+(p.rx/1048576).toFixed(2));
        txD.push(+(p.tx/1048576).toFixed(2));
        const d = p.handshake>0?serverTime-p.handshake:Infinity;
        if(d<180){rxC.push('rgba(39,174,96,0.85)');txC.push('rgba(39,174,96,0.4)');}
        else if(d<86400){rxC.push('rgba(243,156,18,0.85)');txC.push('rgba(243,156,18,0.4)');}
        else{rxC.push('rgba(192,57,43,0.85)');txC.push('rgba(192,57,43,0.4)');}
    });
    if(!totalDataChartInst){const ctx=document.getElementById('totalDataChart');if(!ctx)return;totalDataChartInst=new Chart(ctx.getContext('2d'),{type:'bar',data:{labels,datasets:[{label:'Rx',data:rxD,backgroundColor:rxC},{label:'Tx',data:txD,backgroundColor:txC}]},options:{maintainAspectRatio:false,responsive:true,animation:{duration:400},scales:{y:{beginAtZero:true,ticks:{callback:v=>v>=1024?(v/1024).toFixed(1)+' GB':v.toFixed(0)+' MB'},title:{display:true,text:'Cumulative (MB)'}}},plugins:{tooltip:{callbacks:{label:c=>{const m=c.raw;return c.dataset.label+': '+(m>=1024?(m/1024).toFixed(2)+' GB':m.toFixed(2)+' MB');}}}}}});}
    else{totalDataChartInst.data.labels=labels;totalDataChartInst.data.datasets[0].data=rxD;totalDataChartInst.data.datasets[0].backgroundColor=rxC;totalDataChartInst.data.datasets[1].data=txD;totalDataChartInst.data.datasets[1].backgroundColor=txC;totalDataChartInst.update();}
}

function updateTrendChart(peers) {
    if(!trendChartInst&&document.getElementById('trendChart')){
        const ctx=document.getElementById('trendChart').getContext('2d');
        trendChartInst=new Chart(ctx,{type:'line',data:{labels:[],datasets:[{label:'Throughput / hour',data:[],borderColor:'#2980b9',backgroundColor:'rgba(41,128,185,0.15)',fill:true,tension:0.3,pointRadius:3,pointHoverRadius:5}]},
            options:{maintainAspectRatio:false,responsive:true,
                scales:{y:{beginAtZero:true,ticks:{callback:v=>v>=1024?(v/1024).toFixed(1)+' GB':v.toFixed(0)+' MB'},title:{display:true,text:'Per-hour throughput'}}},
                plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>{const m=c.raw||0;return (m>=1024?(m/1024).toFixed(2)+' GB':m.toFixed(1)+' MB')+' this hour';}}}}}});
    }
    const agg={};
    peers.forEach(p=>{if(p.history){const sk=Object.keys(p.history).sort((a,b)=>a-b);let prev=null;sk.forEach(ts=>{if(!agg[ts])agg[ts]=0;const v=p.history[ts];const bytes=(v&&typeof v==='object')?((v.rx||0)+(v.tx||0)):(v||0);if(prev!==null){let d=bytes-prev;if(d<0)d=bytes;agg[ts]+=d;}else{agg[ts]+=0;}prev=bytes;});}});
    const st=Object.keys(agg).sort((a,b)=>a-b);const labels=[],data=[];
    st.forEach(ts=>{labels.push(new Date(ts*1000).getHours()+':00');data.push(agg[ts]/1048576);});
    const emptyEl=document.getElementById('trendEmpty');
    // Need at least 2 buckets to show a meaningful per-hour delta.
    if(data.length<2){ if(emptyEl)emptyEl.style.display='block'; }
    else { if(emptyEl)emptyEl.style.display='none'; }
    if(trendChartInst){trendChartInst.data.labels=labels;trendChartInst.data.datasets[0].data=data;trendChartInst.update();}
}

// Filter-aware wrapper: 'All Tunnels' shows the aggregate pool; selecting
// a specific tunnel shows THAT tunnel's used/capacity — the meaningful
// "available" for the subnet its peers actually live in.
function updatePieForFilter() {
    if (!lastIpStats) return;
    const selTun  = document.getElementById('filterTun').value;
    const scopeEl = document.getElementById('pieScope');
    if (selTun !== 'ALL') {
        const s = lastSubnets.find(x => x.tun === selTun);
        if (s) {
            if (scopeEl) scopeEl.textContent = '— ' + selTun + (s.cidr ? ' (' + s.cidr + ')' : '');
            renderPieChart(s.used, Math.max(0, s.capacity - s.used), s.capacity);
            return;
        }
    }
    if (scopeEl) scopeEl.textContent = '— all tunnels';
    renderPieChart(lastIpStats.used, lastIpStats.free, lastIpStats.capacity);
}

// Doughnut center readout: exact used/capacity + precise percentage, so
// tiny utilisation can never display as a misleading 0%/100%.
const wgxPieCenterText = {
    id: 'wgxPieCenterText',
    afterDraw(chart) {
        const st = chart.$wgx;
        if (!st || !st.capacity) return;
        const ctx = chart.ctx;
        const meta = chart.getDatasetMeta(0);
        const arc = meta && meta.data && meta.data[0];
        if (!arc) return;
        ctx.save();
        ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillStyle = (getComputedStyle(document.body).color) || '#333';
        ctx.font = '700 16px sans-serif';
        ctx.fillText(st.used + ' / ' + st.capacity, arc.x, arc.y - 9);
        ctx.font = '11px sans-serif';
        ctx.globalAlpha = 0.7;
        ctx.fillText(fmtPctPrecise(st.used, st.capacity) + ' used', arc.x, arc.y + 10);
        ctx.restore();
    }
};

function renderPieChart(used, free, capacity) {
    used = used || 0; free = (free === undefined ? 0 : free);
    capacity = capacity || (used + free);
    // Empty-state: no tunnels/capacity yet.
    const emptyEl = document.getElementById('ipPieEmpty');
    if (capacity <= 0) {
        if (emptyEl) emptyEl.style.display = 'block';
        if (pieChartInst) { pieChartInst.$wgx = null; pieChartInst.data.datasets[0].data = [0, 1]; pieChartInst.update(); }
        return;
    }
    if (emptyEl) emptyEl.style.display = 'none';
    const opts = {
        maintainAspectRatio: false, responsive: true, cutout: '65%',
        plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } },
            tooltip: { callbacks: { label: c => {
                const v = c.raw || 0;
                return c.label + ': ' + v + ' IP' + (v === 1 ? '' : 's') + ' (' + fmtPctPrecise(v, capacity) + ')';
            } } }
        }
    };
    if (!pieChartInst) {
        const ctx = document.getElementById('ipPieChart').getContext('2d');
        pieChartInst = new Chart(ctx, { type:'doughnut',
            data:{ labels:['Used','Available'], datasets:[{ data:[used, free],
                backgroundColor:['rgba(192,57,43,0.85)','rgba(39,174,96,0.85)'],
                borderColor:'rgba(0,0,0,0.15)', borderWidth:1 }] },
            options: opts,
            plugins: [wgxPieCenterText] });
    } else {
        pieChartInst.data.datasets[0].data = [used, free];
        pieChartInst.options = opts;
    }
    pieChartInst.$wgx = { used: used, capacity: capacity };
    pieChartInst.update();
}

// === Subnet Utilisation by Tunnel ===
function renderSubnetTable(subnets) {
    const tbody = document.getElementById('subnetTbody');
    if (!tbody) return;
    if (!subnets || !subnets.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No tunnels configured.</td></tr>';
        return;
    }
    tbody.innerHTML = subnets.map(s => {
        const pct = s.capacity > 0 ? Math.min(100, s.pct) : 0;
        const cls = pct >= 90 ? 'crit' : pct >= 70 ? 'warn' : 'ok';
        const src  = s.source || '';
        const mark = src === 'inferred' ? ' <span class="text-muted" title="Subnet inferred from peer addresses (/24 assumed)" style="cursor:help;">*</span>' : '';
        const cidr = s.cidr ? `<span title="resolved via ${escH(src)}">${escH(s.cidr)}</span>${mark}` : '<span class="text-muted" title="No IPv4 subnet found via kernel, tunnel config, assigned interface, or peers">unresolved</span>';
        const pctLabel = fmtPctPrecise(s.used, s.capacity);
        const fillW = s.used > 0 ? Math.max(pct, 1.5) : 0;   // keep tiny usage visible
        const bar = s.capacity > 0
            ? `<div class="noc-sub-bar"><div class="noc-sub-fill ${cls}" style="width:${fillW}%;"></div><span class="noc-sub-pct">${pctLabel}</span></div>`
            : '<span class="text-muted" style="font-size:11px;">—</span>';
        return `<tr><td><strong>${escH(s.tun)}</strong></td><td style="font-family:'Courier New',monospace;font-size:11px;">${cidr}</td><td>${bar}</td><td class="text-right" style="font-size:11px;">${s.used} / ${s.capacity}</td></tr>`;
    }).join('');
}

// === Top Talkers (24h) — ranked server-side from the telemetry archive ===
function renderTopTalkers(talkers) {
    const list = document.getElementById('topTalkersList');
    if (!list) return;
    if (!talkers || !talkers.length) {
        list.innerHTML = '<li class="text-muted" style="list-style:none;">No traffic recorded in the last 24h.</li>';
        return;
    }
    const medals = ['🥇', '🥈', '🥉'];
    list.innerHTML = talkers.map((tk, i) => {
        const medal = i < 3 ? medals[i] + ' ' : '';
        return `<li>${medal}<strong>${escH(tk.name)}</strong><span class="noc-talker-bytes">${fmtBytes(tk.bytes, 1)}</span><span class="noc-talker-tun"><i class="fa fa-server" style="font-size:9px;"></i> ${escH(tk.tun)}</span></li>`;
    }).join('');
}

// === Country distribution chips (from the geo cache) ===
function renderCountryChips(countries) {
    const wrap = document.getElementById('countryChips');
    if (!wrap) return;
    if (!countries || !countries.length) {
        wrap.innerHTML = '<span class="text-muted" style="font-size:12px;">No geo data yet.</span>';
        return;
    }
    wrap.innerHTML = countries.map(c =>
        `<span class="noc-cchip" title="${escH(c.name)}">${countryFlag(c.code)} ${escH(c.code)}<span class="noc-cchip-n">${c.count}</span></span>`
    ).join('');
}

// === Actions ===
function toggleQuotaExempt(btn, pub, nextVal) {
    btn.disabled = true;
    fetch('/wgx/vpn_wg_dashboard.php', { method:'POST', body: new URLSearchParams({ action:'set_quota_exempt', pub, exempt:nextVal, __csrf_magic:getCsrf() }) })
        .then(r=>r.json()).then(data=>{
            if(data.success){const peer=globalPeerData.find(p=>p.pub===pub);if(peer){peer.quota_exempt=(data.exempt==='1');processData();}}
            else{alert('Failed: '+(data.message||'Unknown'));btn.disabled=false;}
        }).catch(()=>{btn.disabled=false;});
}

function togglePolling() {
    const on = document.getElementById('liveToggle').checked;
    if (pollInterval) clearInterval(pollInterval);
    if (on) pollInterval = setInterval(fetchTelemetry, POLL_RATE_SEC * 1000);
}

// ── Compact/full view toggle ─────────────────────────────────────────────
var isCompact = false;
function toggleCompactView() {
    isCompact = !isCompact;
    const btn = document.getElementById('btnCompactToggle');
    if (btn) btn.innerHTML = isCompact ? '<i class="fa fa-expand"></i>' : '<i class="fa fa-compress"></i>';
    // Hide stat cards and shrink table when compact
    const cards = document.querySelector('.noc-cards');
    if (cards) cards.style.display = isCompact ? 'none' : '';
    document.querySelectorAll('.noc-drawer').forEach(d => d.classList.remove('open'));
    processData();
}

// ── Offline peer alert (checked after each telemetry fetch) ───────────────
var _alertedOffline = {};
function checkOfflineAlerts(peers) {
    const now = Math.floor(Date.now() / 1000);
    peers.forEach(function(p) {
        if (!p.offline_alert_hours || p.offline_alert_hours <= 0) return;
        if (!p.enabled) return;
        const thresholdSecs = p.offline_alert_hours * 3600;
        const offlineSecs = p.handshake > 0 ? (now - p.handshake) : Infinity;
        const key = p.pub;
        if (offlineSecs > thresholdSecs) {
            if (!_alertedOffline[key]) {
                _alertedOffline[key] = true;
                // Fire webhook via export page
                const body = new URLSearchParams({
                    action: 'test_webhook',
                    __csrf_magic: typeof getCsrf === 'function' ? getCsrf() : ''
                });
                // Just show a visible badge on the row - actual webhook fires server-side via cron
                // Mark row with alert badge
                const rows = document.querySelectorAll('.noc-peer-row');
                rows.forEach(function(tr) {
                    if (tr.querySelector('strong') && tr.querySelector('strong').textContent === p.name) {
                        if (!tr.querySelector('.noc-offline-alert')) {
                            const badge = document.createElement('span');
                            badge.className = 'noc-badge noc-offline-alert';
                            badge.style.cssText = 'background:#e74c3c;color:#fff;margin-left:4px;';
                            badge.innerHTML = '<i class="fa fa-bell"></i> ALERT';
                            badge.title = 'Offline for ' + Math.round(offlineSecs/3600) + 'h (threshold: ' + p.offline_alert_hours + 'h)';
                            const nameDiv = tr.querySelector('strong');
                            if (nameDiv) nameDiv.parentNode.appendChild(badge);
                        }
                    }
                });
            }
        } else {
            delete _alertedOffline[key];
        }
    });
}

// ── Dashboard search persistence ─────────────────────────────────────────
(function() {
    const saved = sessionStorage.getItem('wgx_dash_search');
    if (saved) {
        const el = document.getElementById('filterSearch');
        if (el) { el.value = saved; }
    }
    const searchEl = document.getElementById('filterSearch');
    if (searchEl) {
        searchEl.addEventListener('input', function() {
            sessionStorage.setItem('wgx_dash_search', this.value);
        });
    }
})();

document.addEventListener('DOMContentLoaded', () => { fetchTelemetry(); togglePolling(); });
</script>

<?php include("foot.inc"); ?>
