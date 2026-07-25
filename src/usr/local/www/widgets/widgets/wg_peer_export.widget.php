<?php
/*
 * wg_peer_export_widget.php
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

// --- 1. Gather Static Config Data & Create Name/IP Map ---
$a_tunnels = config_get_path('installedpackages/wireguard/tunnels/item', []);
$a_peers   = config_get_path('installedpackages/wireguard/peers/item', []);
$total_tunnels = is_array($a_tunnels) ? count($a_tunnels) : 0;
$total_peers = is_array($a_peers) ? count($a_peers) : 0;

$peer_details = [];
if (is_array($a_peers)) {
    foreach ($a_peers as $p) {
        if (isset($p['publickey'])) {
            $ips = [];
            $allowedips = isset($p['allowedips']) && is_array($p['allowedips']) ? $p['allowedips'] : [];
            $raw_rows = $allowedips['row'] ?? ($allowedips['item'] ?? []);
            if (is_array($raw_rows)) {
                $rows = isset($raw_rows['address']) ? [$raw_rows] : $raw_rows;
                foreach ($rows as $row) {
                    if (is_array($row) && !empty($row['address'])) {
                        $ips[] = $row['address'];
                    }
                }
            }
            $peer_details[$p['publickey']] = [
                'name' => $p['descr'] ?? 'Unknown Peer',
                'vip'  => !empty($ips) ? implode(', ', $ips) : 'No IP'
            ];
        }
    }
}

// --- 2. Gather Live Telemetry ---
$wg_bin = is_executable('/usr/local/bin/wg') ? '/usr/local/bin/wg' : '/usr/bin/wg';
$rx_total = 0;
$tx_total = 0;
$online_peers = 0;

$tx_rx_map = [];
$handshake_map = [];
$endpoints = [];

if (!empty($wg_bin)) {
    // Single `wg show all dump` call replaces three separate exec() calls.
    // Columns: interface  pubkey  preshared  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
    $dump_out = [];
    exec(escapeshellarg($wg_bin) . ' show all dump 2>/dev/null', $dump_out);
    $now = time();
    foreach ($dump_out as $line) {
        $parts = preg_split('/\s+/', trim($line));
        // Interface/server lines have 5 columns; peer lines have 9
        if (count($parts) < 9) continue;
        $pub = $parts[1];
        $ep  = $parts[3]; // endpoint ip:port or (none)
        $hs  = (int)$parts[5];
        $rx  = (int)$parts[6];
        $tx  = (int)$parts[7];

        // Bandwidth
        $rx_total += $rx;
        $tx_total += $tx;
        if ($rx > 0 || $tx > 0) {
            $tx_rx_map[$pub] = ['rx' => $rx, 'tx' => $tx];
        }

        // Handshakes
        if ($hs > 0) {
            $handshake_map[$pub] = $hs;
            if (($now - $hs) < 180) {
                $online_peers++;
            }
        }

        // Endpoints
        if ($ep !== '(none)') {
            $last_colon = strrpos($ep, ':');
            $endpoints[$pub] = $last_colon !== false
            ? trim(substr($ep, 0, $last_colon), '[]')
            : $ep;
        }
    }
}

// --- 3. Build Active Peer List ---
$active_list = [];
foreach ($handshake_map as $pub => $hs) {
    if ($hs > 0) {
        $name = $peer_details[$pub]['name'] ?? substr($pub, 0, 8) . '...';
        $vip  = $peer_details[$pub]['vip'] ?? 'N/A';
        $ep   = $endpoints[$pub] ?? 'Offline';
        $rx   = $tx_rx_map[$pub]['rx'] ?? 0;
        $tx   = $tx_rx_map[$pub]['tx'] ?? 0;

        $ep_ip = $ep;
        $ep_port = '';
        if ($ep !== 'Offline') {
            $last_colon = strrpos($ep, ':');
            if ($last_colon !== false) {
                $ep_ip = trim(substr($ep, 0, $last_colon), '[]');
                $ep_port = substr($ep, $last_colon + 1);
            }
        }

        $active_list[] = [
            'name' => $name,
            'vip' => $vip,
            'ep_ip' => $ep_ip,
            'ep_port' => $ep_port,
            'rx' => $rx,
            'tx' => $tx,
            'hs' => $hs
        ];
    }
}

// Sort by most recent connection
usort($active_list, function($a, $b) { return $b['hs'] <=> $a['hs']; });

function wgx_format_bytes($bytes) {
    if ($bytes == 0) return "0.00 B";
    $s = array('B', 'KB', 'MB', 'GB', 'TB');
    $e = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $e), 2) . ' ' . $s[$e];
}

function wgx_time_ago($timestamp) {
    $diff = time() - $timestamp;
    if ($diff < 60) return $diff . "s ago";
    if ($diff < 3600) return round($diff / 60) . "m ago";
    if ($diff < 86400) return round($diff / 3600) . "h ago";
    return round($diff / 86400) . "d ago";
}

$widgetperiod = 30;
?>
<script>
if (typeof widget_doreload === 'undefined') {
    setInterval(function() {
        if (typeof ajax_object !== 'undefined') {
            $('#wgx-widget-container').load(window.location.href + ' #wgx-widget-container > *');
        }
    }, 30000);
}
</script>
<?php
?>

<style>
/* Theme-agnostic widget styles — inherit colours from the active pfSense
 theme* rather than hardcoding light-mode values that break in dark mode. */
.wgx-table th { position: sticky; top: 0; z-index: 10; }
.wgx-stat-box { text-align: center; padding: 10px 5px; border: 1px solid; border-color: rgba(128,128,128,0.25); border-radius: 4px; margin-bottom: 10px; }
.wgx-stat-title { font-size: 10px; text-transform: uppercase; opacity: 0.7; font-weight: bold; margin-bottom: 3px; }
.wgx-stat-val { font-size: 16px; font-weight: bold; }
.wgx-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
.wgx-dot-online { background-color: #5cb85c; box-shadow: 0 0 4px #5cb85c; }
.wgx-dot-idle { background-color: #f0ad4e; }
.wgx-dot-offline { background-color: #d9534f; }
</style>

<div id="wgx-widget-container" class="content">
    <div class="row" style="margin: 0 -5px;">
        <div class="col-xs-3" style="padding: 0 5px;">
            <div class="wgx-stat-box">
                <div class="wgx-stat-title">Tunnels</div>
                <div class="wgx-stat-val text-primary"><?= $total_tunnels ?></div>
            </div>
        </div>
        <div class="col-xs-3" style="padding: 0 5px;">
            <div class="wgx-stat-box">
                <div class="wgx-stat-title">Online</div>
                <div class="wgx-stat-val text-success"><?= $online_peers ?> <span style="font-size:10px; color:#aaa; font-weight:normal;">/ <?= $total_peers ?></span></div>
            </div>
        </div>
        <div class="col-xs-3" style="padding: 0 5px;">
            <div class="wgx-stat-box" title="Total Download">
                <div class="wgx-stat-title"><i class="fa fa-arrow-down text-success"></i> Rx Data</div>
                <div class="wgx-stat-val" style="font-size: 13px; margin-top:2px;"><?= wgx_format_bytes($rx_total) ?></div>
            </div>
        </div>
        <div class="col-xs-3" style="padding: 0 5px;">
            <div class="wgx-stat-box" title="Total Upload">
                <div class="wgx-stat-title"><i class="fa fa-arrow-up text-info"></i> Tx Data</div>
                <div class="wgx-stat-val" style="font-size: 13px; margin-top:2px;"><?= wgx_format_bytes($tx_total) ?></div>
            </div>
        </div>
    </div>

    <div style="max-height: 280px; overflow-y: auto; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 10px;">
        <table class="table table-hover table-condensed wgx-table" style="margin-bottom: 0; font-size: 11px;">
            <thead>
                <tr>
                    <th>Peer & Internal IP</th>
                    <th>Public Endpoint</th>
                    <th>Data (Rx/Tx)</th>
                    <th class="text-right">Last Seen</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($active_list)): ?>
                <tr>
                    <td colspan="4" class="text-center text-muted" style="padding: 15px;">No active connections found.</td>
                </tr>
                <?php else: foreach ($active_list as $p):
                    $diff = time() - $p['hs'];
                    $dot_class = 'wgx-dot-offline';
                    if ($diff < 180) $dot_class = 'wgx-dot-online';
                    elseif ($diff < 86400) $dot_class = 'wgx-dot-idle';
                ?>
                <tr>
                    <td>
                    <a href="/wgx/vpn_wg_export.php?search=<?= urlencode($p['name']) ?>" style="text-decoration:none; color:inherit;">
                    <span class="wgx-dot <?= $dot_class ?>"></span> <strong><?= htmlspecialchars($p['name']) ?></strong></a><br>
                    <span class="text-muted" style="margin-left: 12px;"><i class="fa fa-sitemap"></i> <?= htmlspecialchars($p['vip']) ?></span>
                    </td>
                    <td>
                        <?php if ($p['ep_ip'] === 'Offline'): ?>
                            <span class="text-muted">Unknown</span>
                        <?php else: ?>
                            <span class="text-primary"><?= htmlspecialchars($p['ep_ip']) ?></span><br>
                            <span class="text-muted" style="font-size:10px;">Port: <?= htmlspecialchars($p['ep_port']) ?></span>
                        <?php endif; ?>
                    </td>
                    <td style="white-space: nowrap;">
                        <span class="text-success"><i class="fa fa-arrow-down"></i> <?= wgx_format_bytes($p['rx']) ?></span><br>
                        <span class="text-info"><i class="fa fa-arrow-up"></i> <?= wgx_format_bytes($p['tx']) ?></span>
                    </td>
                    <td class="text-right text-muted" style="vertical-align: middle;">
                        <?= wgx_time_ago($p['hs']) ?>
                    </td>
                </tr>
                <?php endforeach; endif; ?>
            </tbody>
        </table>
    </div>

    <div class="text-center">
        <div class="btn-group">
            <a href="/wgx/vpn_wg_dashboard.php" class="btn btn-info btn-xs" title="Live Telemetry Dashboard">
                <i class="fa fa-bar-chart"></i> NOC Dash
            </a>
            <a href="/wgx/vpn_wg_setup.php" class="btn btn-success btn-xs" title="Setup Wizard">
                <i class="fa fa-magic"></i> Wizard
            </a>
            <a href="/wgx/vpn_wg_export.php" class="btn btn-primary btn-xs" title="Manage Peers">
                <i class="fa fa-cogs"></i> Manage
            </a>
        </div>
    </div>
</div>
