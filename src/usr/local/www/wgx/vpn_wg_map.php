<?php
/*
 * vpn_wg_map.php
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

// --- Settings ---
$wgx_map_settings  = config_get_path('installedpackages/wgexport/config/0', []);
// $geo_enabled gates IP *reputation* flags (proxy/tor/hosting) — opt-in.
// Basic geo (lat/lon/city/country) for the map always runs regardless.
$geo_enabled       = ($wgx_map_settings['enable_geo'] ?? 'false') === 'true';

// --- Gather peers ---
$a_peers = config_get_path('installedpackages/wireguard/peers/item', []);
if (!is_array($a_peers))           { $a_peers = []; }
elseif (!empty($a_peers) && !isset($a_peers[0])) { $a_peers = [$a_peers]; }

$wg_bin = is_executable('/usr/local/bin/wg') ? '/usr/local/bin/wg'
: (is_executable('/usr/bin/wg')       ? '/usr/bin/wg' : '');

// Single `wg show all dump` call replaces three separate exec() calls.
// Peer line columns: interface  pubkey  preshared  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
$handshakes = [];
$endpoints  = [];
$telemetry  = [];
if (!empty($wg_bin)) {
    $dump_out = [];
    exec(escapeshellarg($wg_bin) . ' show all dump 2>/dev/null', $dump_out);
    $now_dump = time();
    foreach ($dump_out as $line) {
        $p = preg_split('/\s+/', trim($line));
        // Peer lines have 9 columns; interface/server lines have 5 — skip those
        if (count($p) < 9) continue;
        $pub = $p[1];
        $ep  = $p[3];
        $hs  = (int)$p[5];
        $rx  = (int)$p[6];
        $tx  = (int)$p[7];

        if ($hs > 0) {
            $handshakes[$pub] = $hs;
        }

        if ($ep !== '(none)') {
            $last_colon      = strrpos($ep, ':');
            $endpoints[$pub] = $last_colon !== false
            ? trim(substr($ep, 0, $last_colon), '[]')
            : $ep;
        }

        if ($rx > 0 || $tx > 0) {
            $telemetry[$pub] = ['rx' => $rx, 'tx' => $tx];
        }
    }
}

// Reputation / geolocation cache — always loaded (geo coords are not sensitive;
// reputation flags are masked below unless $geo_enabled is true)
$rep_cache = [];
$rep_file  = '/var/db/wgx_ip_reputation.json';
if (file_exists($rep_file)) {
    $rep_cache = json_decode(file_get_contents($rep_file), true) ?? [];
}

// GPS check-in cache (actual device locations from vpn_wg_checkin.php)
$gps_file  = '/var/db/wgx_gps_locations.json';
$gps_cache = [];
if (file_exists($gps_file)) {
    $gps_cache = json_decode(file_get_contents($gps_file), true) ?? [];
}

// Prune GPS entries older than 30 days
$gps_changed = false;
foreach ($gps_cache as $key => $entry) {
    if ((time() - ($entry['updated'] ?? 0)) > 86400 * 30) {
        unset($gps_cache[$key]);
        $gps_changed = true;
    }
}
if ($gps_changed) {
    file_put_contents($gps_file, json_encode($gps_cache, JSON_PRETTY_PRINT));
}

// WAN IP fallback for local-network peers
$wan_ip = '';
if (function_exists('get_interface_ip')) {
    $wan_ip = get_interface_ip('wan') ?? '';
}
if (!$wan_ip) {
    $all_ifaces = config_get_path('interfaces', []);
    foreach ($all_ifaces as $iface) {
        if (is_array($iface) && ($iface['ipaddr'] ?? '') !== 'dhcp' && !empty($iface['ipaddr'])
            && filter_var($iface['ipaddr'], FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
            $wan_ip = $iface['ipaddr'];
            break;
        }
    }
}

// Fetch geo for WAN IP if not yet cached — gated by geo_enabled (user must opt in)
if ($geo_enabled && $wan_ip && !isset($rep_cache[$wan_ip])) {
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'user_agent' => 'WGSuite/1.2']]);
    $raw = @file_get_contents(
        "http://ip-api.com/json/{$wan_ip}?fields=status,isp,org,lat,lon,city,country,countryCode",
        false, $ctx
    );
    if ($raw) {
        $api = json_decode($raw, true);
        if (is_array($api) && ($api['status'] ?? '') === 'success') {
            $rep_cache[$wan_ip] = [
                'flags'        => [],
                'isp'          => $api['isp']         ?? '',
                'org'          => $api['org']         ?? '',
                'lat'          => $api['lat']         ?? null,
                'lon'          => $api['lon']         ?? null,
                'city'         => $api['city']        ?? '',
                'country'      => $api['country']     ?? '',
                'country_code' => $api['countryCode'] ?? '',
                'checked'      => time(),
            ];
            file_put_contents($rep_file, json_encode($rep_cache, JSON_PRETTY_PRINT));
        }
    }
}

function wgx_map_fmt_bytes($bytes) {
    if ($bytes <= 0) { return '0 B'; }
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = min((int)floor(log($bytes, 1024)), 4);
    return round($bytes / pow(1024, $i), 2) . ' ' . $u[$i];
}

// Build markers
$markers      = [];
$no_geo       = [];
$peer_count   = 0;
$online_count = 0;
$mapped_count = 0;

foreach ($a_peers as $peer) {
    if (!is_array($peer)) { continue; }
    $peer_count++;
    $pub    = $peer['publickey'] ?? '';
    $descr  = htmlspecialchars($peer['descr'] ?? 'Unknown', ENT_QUOTES);
    $tun    = htmlspecialchars($peer['tun']   ?? '',        ENT_QUOTES);
    $hs     = $handshakes[$pub] ?? 0;
    $online = $hs && (time() - $hs) < 180;
    $ep_ip  = $endpoints[$pub] ?? '';
    $rx     = $telemetry[$pub]['rx'] ?? 0;
    $tx     = $telemetry[$pub]['tx'] ?? 0;
    $tags   = htmlspecialchars($peer['wgx_tags'] ?? '', ENT_QUOTES);

    if ($online) { $online_count++; }

    $diff   = $hs ? (time() - $hs) : 0;
    $hs_str = !$hs          ? 'Never'
            : ($diff < 60   ? $diff . 's ago'
            : ($diff < 3600 ? round($diff / 60)    . 'm ago'
            : ($diff < 86400? round($diff / 3600)  . 'h ago'
            :                 round($diff / 86400) . 'd ago')));

    if (!$ep_ip) {
        $no_geo[] = ['descr' => $descr, 'reason' => 'No endpoint — peer has not connected yet'];
        continue;
    }

    // --- GPS check-in takes priority over IP geolocation ---
    $gps_entry = $gps_cache[$pub] ?? null;
    $gps_age   = $gps_entry ? (time() - ($gps_entry['updated'] ?? 0)) : null;
    $use_gps   = ($gps_entry && $gps_age !== null && $gps_age < (86400 * 7));  // discard if >7 days

    $is_local  = filter_var($ep_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    $lookup_ip = $is_local ? $wan_ip : $ep_ip;

    // If this IP isn't cached yet, fetch it inline now — requires geo opt-in
    if ($geo_enabled && !$use_gps && $lookup_ip && !isset($rep_cache[$lookup_ip])) {
        $ctx_m = stream_context_create(['http' => ['timeout' => 5, 'user_agent' => 'WGSuite/1.2']]);
        $raw_m = @file_get_contents(
            "http://ip-api.com/json/{$lookup_ip}?fields=status,proxy,hosting,isp,org,lat,lon,city,country,countryCode",
            false, $ctx_m
        );
        if ($raw_m) {
            $api_m = json_decode($raw_m, true);
            if (is_array($api_m) && ($api_m['status'] ?? '') === 'success') {
                $rep_cache[$lookup_ip] = [
                    'flags'        => array_filter([
                        $api_m['proxy']   ?? false ? 'proxy'   : null,
                        $api_m['hosting'] ?? false ? 'hosting' : null,
                    ]),
                    'isp'          => $api_m['isp']         ?? '',
                    'org'          => $api_m['org']         ?? '',
                    'lat'          => $api_m['lat']         ?? null,
                    'lon'          => $api_m['lon']         ?? null,
                    'city'         => $api_m['city']        ?? '',
                    'country'      => $api_m['country']     ?? '',
                    'country_code' => $api_m['countryCode'] ?? '',
                    'checked'      => time(),
                ];
                // Persist so the next page load (and wgx_expire.php) benefit too
                @file_put_contents($rep_file, json_encode($rep_cache, JSON_PRETTY_PRINT));
            }
        }
    }

    // Resolve final coordinates: GPS > IP-geo
    if ($use_gps) {
        $lat        = (float)$gps_entry['lat'];
        $lon        = (float)$gps_entry['lon'];
        $city       = 'GPS location';
        $country    = $gps_entry['name'] ?? $descr;
        $isp        = 'Accuracy: ' . ($gps_entry['acc'] ? '±' . round($gps_entry['acc']) . 'm' : 'unknown');
        $flags_str  = '';
        $loc_source = 'gps';
        $gps_age_str = $gps_age < 60   ? $gps_age . 's ago'
                     : ($gps_age < 3600 ? round($gps_age / 60) . 'm ago'
                     : ($gps_age < 86400 ? round($gps_age / 3600) . 'h ago'
                     :                     round($gps_age / 86400) . 'd ago'));
    } else {
        $geo = ($lookup_ip && isset($rep_cache[$lookup_ip])) ? $rep_cache[$lookup_ip] : null;
        if (!$geo || !isset($geo['lat']) || $geo['lat'] === null) {
            $reason   = !$geo_enabled
                ? "Geo disabled â enable IP Geolocation in Global Settings to show this peer"
                : ($is_local
                    ? "Local network peer (endpoint: {$ep_ip}) â WAN IP geo lookup failed"
                    : "Geo lookup failed for {$ep_ip} â ip-api.com may be temporarily unavailable");
            $no_geo[] = ['descr' => $descr, 'reason' => $reason];
            continue;
        }
        $lat        = (float)$geo['lat'];
        $lon        = (float)$geo['lon'];
        $city       = $geo['city']    ?? '';
        $country    = $geo['country'] ?? '';
        $isp        = $geo['isp']     ?? '';
        $flags_str  = ($geo_enabled && !empty($geo['flags']))
            ? implode(', ', array_map('strtoupper', $geo['flags'])) : '';
        $loc_source  = 'ip';
        $gps_age_str = '';
    }

    // Only surface reputation flags if user has opted into IP reputation checking
    $mapped_count++;
    $markers[] = [
        'lat'        => $lat,
        'lon'        => $lon,
        'descr'      => $descr,
        'tun'        => $tun,
        'tags'       => $tags,
        'online'     => $online,
        'is_local'   => $is_local,
        'ep_ip'      => htmlspecialchars($ep_ip, ENT_QUOTES),
        'isp'        => htmlspecialchars($isp,     ENT_QUOTES),
        'city'       => htmlspecialchars($city,    ENT_QUOTES),
        'country'    => htmlspecialchars($country, ENT_QUOTES),
        'flags'      => $flags_str,
        'hs'         => $hs_str,
        'dl'         => wgx_map_fmt_bytes($tx),
        'ul'         => wgx_map_fmt_bytes($rx),
        'loc_source' => $loc_source,
        'gps_age'    => $gps_age_str,
        'gps_stale'  => ($loc_source === 'gps' && $gps_age !== null && $gps_age > 86400),
    ];
}

$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("Map")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
include("head.inc");
?>
<style>
@media (max-width: 767px) {
    #mapContainer, .leaflet-container { height: 320px !important; }
    .col-sm-3, .col-sm-4, .col-sm-8, .col-sm-9 { width: 100% !important; margin-bottom: 6px; }
    .panel-body { padding: 8px; }
}
</style>
<?php

$tab_array   = [];
$tab_array[] = [gettext("Dashboard"), false, "/wgx/vpn_wg_dashboard.php"];
$tab_array[] = [gettext("Export"),    false, "/wgx/vpn_wg_export.php"];
$tab_array[] = [gettext("Setup"),     false, "/wgx/vpn_wg_setup.php"];
$tab_array[] = [gettext("Audit"),     false, "/wgx/vpn_wg_audit.php"];
$tab_array[] = [gettext("Map"),       true,  "/wgx/vpn_wg_map.php"];
display_top_tabs($tab_array);
?>

<!-- Leaflet CSS inlined to avoid pfSense CSP blocking external stylesheets -->
<style>
/* ---- Leaflet core layout ---- */
.leaflet-pane,.leaflet-tile,.leaflet-marker-icon,.leaflet-marker-shadow,
.leaflet-tile-container,.leaflet-pane>svg,.leaflet-pane>canvas,
.leaflet-zoom-box,.leaflet-image-layer,.leaflet-layer{position:absolute;left:0;top:0}
.leaflet-container{overflow:hidden}
.leaflet-tile,.leaflet-marker-icon,.leaflet-marker-shadow{-webkit-user-select:none;-moz-user-select:none;user-select:none;-webkit-user-drag:none}
.leaflet-tile::selection{background:transparent}
.leaflet-safari .leaflet-tile{image-rendering:crisp-edges}
.leaflet-safari .leaflet-zoom-hide{visibility:hidden}
.leaflet-pane{z-index:400}
.leaflet-tile-pane{z-index:200}
.leaflet-overlay-pane{z-index:400}
.leaflet-shadow-pane{z-index:500}
.leaflet-marker-pane{z-index:600}
.leaflet-tooltip-pane{z-index:650}
.leaflet-popup-pane{z-index:700}
.leaflet-map-pane canvas{z-index:100}
.leaflet-map-pane svg{z-index:200}
.leaflet-control{position:relative;z-index:800;pointer-events:visiblePainted;pointer-events:auto}
.leaflet-top,.leaflet-bottom{position:absolute;z-index:1000;pointer-events:none}
.leaflet-top{top:0}.leaflet-right{right:0}.leaflet-bottom{bottom:0}.leaflet-left{left:0}
.leaflet-control{float:left;clear:both}
.leaflet-right .leaflet-control{float:right}
.leaflet-top .leaflet-control{margin-top:10px}
.leaflet-bottom .leaflet-control{margin-bottom:10px}
.leaflet-left .leaflet-control{margin-left:10px}
.leaflet-right .leaflet-control{margin-right:10px}
.leaflet-fade-anim .leaflet-popup{opacity:0;-webkit-transition:opacity .2s linear;transition:opacity .2s linear}
.leaflet-fade-anim .leaflet-map-pane .leaflet-popup{opacity:1}
.leaflet-zoom-animated{-webkit-transform-origin:0 0;transform-origin:0 0}
svg.leaflet-zoom-animated{will-change:transform}
.leaflet-zoom-anim .leaflet-zoom-animated{-webkit-transition:-webkit-transform .25s cubic-bezier(0,0,.25,1);transition:transform .25s cubic-bezier(0,0,.25,1)}
.leaflet-zoom-anim .leaflet-tile,.leaflet-pan-anim .leaflet-tile{-webkit-transition:none;transition:none}
.leaflet-zoom-anim .leaflet-zoom-animated{will-change:transform}
.leaflet-interactive{cursor:pointer}
.leaflet-grab{cursor:-webkit-grab;cursor:grab}
.leaflet-crosshair,.leaflet-crosshair .leaflet-interactive{cursor:crosshair}
.leaflet-popup-pane,.leaflet-control{cursor:auto}
.leaflet-dragging .leaflet-grab,.leaflet-dragging .leaflet-grab .leaflet-interactive,.leaflet-dragging .leaflet-marker-draggable{cursor:move;cursor:-webkit-grabbing;cursor:grabbing}
.leaflet-marker-icon,.leaflet-marker-shadow,.leaflet-image-layer,.leaflet-pane>svg path,.leaflet-tile-container{pointer-events:none}
.leaflet-marker-icon.leaflet-interactive,.leaflet-image-layer.leaflet-interactive,.leaflet-pane>svg path.leaflet-interactive,svg.leaflet-image-layer.leaflet-interactive path{pointer-events:visiblePainted;pointer-events:auto}
.leaflet-container{background:#ddd;outline-offset:1px}
.leaflet-container a{color:#0078A8}
.leaflet-zoom-box{border:2px dotted #38f;background:rgba(255,255,255,.5)}
.leaflet-container{font-family:Helvetica Neue,Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5}
.leaflet-bar{box-shadow:0 1px 5px rgba(0,0,0,.65);border-radius:4px}
.leaflet-bar a{background-color:#fff;border-bottom:1px solid #ccc;width:26px;height:26px;line-height:26px;display:block;text-align:center;text-decoration:none;color:#000}
.leaflet-bar a:hover,.leaflet-bar a:focus{background-color:#f4f4f4}
.leaflet-bar a:first-child{border-top-left-radius:4px;border-top-right-radius:4px}
.leaflet-bar a:last-child{border-bottom-left-radius:4px;border-bottom-right-radius:4px;border-bottom:none}
.leaflet-bar a.leaflet-disabled{cursor:default;background-color:#f4f4f4;color:#bbb}
.leaflet-touch .leaflet-bar a{width:30px;height:30px;line-height:30px}
.leaflet-control-zoom-in,.leaflet-control-zoom-out{font:bold 18px Lucida Console,Monaco,monospace;text-indent:1px}
.leaflet-control-attribution{background:#fff;background:rgba(255,255,255,.8);margin:0}
.leaflet-control-attribution,.leaflet-control-scale-line{padding:0 5px;color:#333;font-size:11px}
.leaflet-left .leaflet-control-scale{margin-left:5px}
.leaflet-bottom .leaflet-control-scale{margin-bottom:5px}
.leaflet-control-scale-line{border:2px solid #777;border-top:none;line-height:1.1;padding:2px 5px 1px;font-size:11px;white-space:nowrap;overflow:hidden;box-sizing:border-box;background:#fff;background:rgba(255,255,255,.5)}
.leaflet-control-scale-line:not(:first-child){border-top:2px solid #777;border-bottom:none;margin-top:-2px}
.leaflet-control-scale-line:not(:first-child):not(:last-child){border-bottom:2px solid #777}
.leaflet-touch .leaflet-control-attribution,.leaflet-touch .leaflet-control-layers,.leaflet-touch .leaflet-bar{box-shadow:none}
.leaflet-touch .leaflet-control-layers,.leaflet-touch .leaflet-bar{border:2px solid rgba(0,0,0,.2);background-clip:padding-box}
.leaflet-popup{position:absolute;text-align:center;margin-bottom:20px}
.leaflet-popup-content-wrapper{padding:1px;text-align:left;border-radius:12px}
.leaflet-popup-content{margin:13px 24px 13px 20px;line-height:1.3;font-size:12px;min-height:1px;min-width:180px}
.leaflet-popup-content p{margin:17px 0 11px}
.leaflet-popup-tip-container{width:40px;height:20px;position:absolute;left:50%;margin-left:-20px;overflow:hidden;pointer-events:none}
.leaflet-popup-tip{width:17px;height:17px;padding:1px;margin:-10px auto 0;pointer-events:auto;-webkit-transform:rotate(45deg);transform:rotate(45deg)}
.leaflet-popup-content-wrapper,.leaflet-popup-tip{background:#fff;color:#333;box-shadow:0 3px 14px rgba(0,0,0,.4)}
.leaflet-container a.leaflet-popup-close-button{position:absolute;top:0;right:0;border:none;text-align:center;width:24px;height:24px;font:16px/24px Tahoma,Verdana,sans-serif;color:#757575;text-decoration:none;background:transparent}
.leaflet-container a.leaflet-popup-close-button:hover,.leaflet-container a.leaflet-popup-close-button:focus{color:#585858}
.leaflet-popup-scrolled{overflow:auto}
.leaflet-tooltip{position:absolute;padding:6px;background-color:#fff;border:1px solid #fff;border-radius:3px;color:#222;white-space:nowrap;-webkit-user-select:none;user-select:none;pointer-events:none;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.leaflet-tooltip.leaflet-interactive{cursor:pointer;pointer-events:auto}
.leaflet-tooltip-top:before,.leaflet-tooltip-bottom:before,.leaflet-tooltip-left:before,.leaflet-tooltip-right:before{position:absolute;pointer-events:none;border:6px solid transparent;background:transparent;content:""}
.leaflet-tooltip-bottom{margin-top:6px}.leaflet-tooltip-top{margin-top:-6px}
.leaflet-tooltip-top:before{bottom:0;margin-bottom:-12px;border-top-color:#fff}
.leaflet-tooltip-bottom:before{top:0;margin-top:-12px;margin-left:-6px;border-bottom-color:#fff}
.leaflet-tooltip-left:before{right:0;margin-right:-12px;margin-top:-6px;border-left-color:#fff}
.leaflet-tooltip-right:before{left:0;margin-left:-12px;margin-top:-6px;border-right-color:#fff}
/* ---- WGX map custom ---- */
#wgx-map{height:560px;width:100%;border-radius:4px;z-index:1}
.wgx-map-legend{background:#fff;padding:8px 12px;border-radius:4px;box-shadow:0 1px 4px rgba(0,0,0,.2);font-size:12px;line-height:1.8}
.wgx-dot-lg{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:5px;vertical-align:middle}
.leaflet-popup-content strong{font-size:13px}
</style>

<?php if (!$geo_enabled): ?>
<div class="alert alert-warning" style="margin-bottom:15px;">
    <i class="fa fa-exclamation-triangle"></i>
    <strong>IP Geolocation is disabled.</strong>
    Enable <strong>IP Reputation &amp; Geolocation</strong> in
    <a href="/wgx/vpn_wg_export.php">WG Suite &rarr; Export &rarr; Global Settings</a>
    to populate the map. No data will be sent to external services until you opt in.
</div>
<?php endif; ?>

<div class="alert alert-info" style="margin-bottom:15px;">
    <i class="fa fa-info-circle"></i>
    <strong>How this map works:</strong>
    Markers show where each peer's traffic enters the internet — not the device's physical location.
    Peers on <strong>mobile data</strong> show their carrier's regional IP.
    Peers on <strong>home WiFi</strong> show your WAN IP (they share your internet connection).
    Exact device location is never tracked or collected.
    Map tiles are loaded from <a href="https://www.openstreetmap.org" target="_blank">OpenStreetMap</a>.
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">
            <i class="fa fa-globe"></i> Peer World Map
            <span class="pull-right" style="font-size:12px;font-weight:normal;margin-top:2px;">
                <span class="text-muted"><?= $peer_count ?> peers &nbsp;|&nbsp;</span>
                <span class="text-success"><i class="fa fa-circle"></i> <?= $online_count ?> online</span>
                <span class="text-muted">&nbsp;|&nbsp;</span>
                <span class="text-primary"><i class="fa fa-map-marker"></i> <?= $mapped_count ?> mapped</span>
            </span>
        </h2>
    </div>
    <div class="panel-body" style="padding:10px;">
    <div style="position:relative;">
    <div id="mapEmptyNotice" style="display:none; position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); z-index:1000; background:rgba(255,255,255,0.93); border:1px solid #ddd; border-radius:8px; padding:18px 24px; text-align:center; max-width:320px; box-shadow:0 2px 12px rgba(0,0,0,0.15);">
    <i class="fa fa-map-o fa-2x text-muted" style="margin-bottom:8px;"></i><br>
    <strong>No peer locations found</strong><br>
    <small class="text-muted">Enable geolocation in <a href="/wgx/vpn_wg_export.php">Global Settings</a>, or have peers submit GPS check-ins via their export page.</small>
    </div>
    <div id="wgx-map"></div>
    </div>
    </div>
</div>

<?php if (!empty($no_geo)): ?>
<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><i class="fa fa-exclamation-circle text-warning"></i> Peers Without Location Data</h2>
    </div>
    <div class="panel-body">
        <table class="table table-condensed table-striped" style="margin-bottom:0;">
            <thead><tr><th>Peer</th><th>Reason</th></tr></thead>
            <tbody>
            <?php foreach ($no_geo as $ng): ?>
                <tr>
                    <td><strong><?= $ng['descr'] ?></strong></td>
                    <td class="text-muted"><?= htmlspecialchars($ng['reason']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>

<script src="/leaflet.min.js"></script>
<script>
(function () {
    var markersData = <?= json_encode($markers, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;

    var map = L.map('wgx-map', { zoomControl: true, scrollWheelZoom: true }).setView([30, 10], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
        maxZoom: 18
    }).addTo(map);

    /* ---- Group markers sharing the same coordinates (3 dp ~ 100 m) ---- */
    var groups = {};
    markersData.forEach(function (m) {
        var key = m.lat.toFixed(3) + '_' + m.lon.toFixed(3);   // underscore avoids colon
        if (!groups[key]) {
            groups[key] = { lat: m.lat, lon: m.lon, peers: [], idx: 0 };
        }
        groups[key].peers.push(m);
    });

    /* ---- Pin icon: single peer 28x36, cluster 36x44 with count badge ---- */
    function makeIcon(online, flagged, isLocal, count, locSource) {
        var multi  = count > 1;
        var w = multi ? 36 : 28;
        var h = multi ? 44 : 36;
        var cx = w / 2;
        var cy = h * 0.38;
        var r  = cx * 0.50;
        var colour = locSource === 'gps' ? '#8e44ad'   // purple = real GPS
                   : flagged             ? '#f0ad4e'
                   : isLocal             ? '#337ab7'
                   : online              ? '#5cb85c'
                   :                       '#d9534f';
        /* Simple teardrop: circle top, pointed bottom */
        var svg = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">',
            '<ellipse cx="' + cx + '" cy="' + cy + '" rx="' + cx + '" ry="' + cy + '" fill="' + colour + '" stroke="#fff" stroke-width="2"/>',
            '<polygon points="' + (cx - cx*0.45) + ',' + (cy + cy*0.7) + ' ' + cx + ',' + h + ' ' + (cx + cx*0.45) + ',' + (cy + cy*0.7) + '" fill="' + colour + '" stroke="#fff" stroke-width="1"/>',
            '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="#fff" fill-opacity="0.92"/>'
        ].join('');
        if (multi) {
            svg += '<text x="' + cx + '" y="' + (cy + 4) + '" text-anchor="middle" font-size="12" font-weight="bold" font-family="Arial,sans-serif" fill="' + colour + '">' + count + '</text>';
        }
        svg += '</svg>';
        return L.divIcon({ html: svg, className: '', iconSize: [w, h], iconAnchor: [cx, h], popupAnchor: [0, -(h + 4)] });
    }

    /* ---- Popup content for one peer inside a group ---- */
    function buildPopupContent(group) {
        var m       = group.peers[group.idx];
        var total   = group.peers.length;
        var flagged = m.flags !== '';
        var isLocal = m.is_local === true;
        var gkey    = m.lat.toFixed(3) + '_' + m.lon.toFixed(3);

        var statusDot = m.online
            ? '<span style="color:#5cb85c">&#9679;</span> <strong style="color:#5cb85c">Online</strong>'
            : '<span style="color:#d9534f">&#9679;</span> <span style="color:#d9534f">Offline</span>';

        var repBadge = flagged
            ? '<br><span style="background:#d9534f;color:#fff;padding:1px 5px;border-radius:3px;font-size:10px">&#9888; ' + m.flags + '</span>'
            : '';

        var tagHtml = '';
        if (m.tags) {
            tagHtml = '<br>' + m.tags.split(',').map(function (t) {
                return '<span style="background:#337ab7;color:#fff;padding:1px 5px;border-radius:3px;font-size:10px;margin-right:2px">' + t.trim() + '</span>';
            }).join('');
        }

        var localNote = isLocal
            ? '<tr><td style="color:#777">Connection</td><td><span style="color:#337ab7">&#8962; Local Network</span><br><small style="color:#999">Location is your WAN IP</small></td></tr>'
            : '';

        /* Nav bar uses data-* attrs — no inline JS string escaping needed */
        var navBar = '';
        if (total > 1) {
            var onlineCount = group.peers.filter(function (p) { return p.online; }).length;
            navBar = '<div style="display:flex;align-items:center;justify-content:space-between;background:#f0f4f8;border:1px solid #d0d8e0;border-radius:4px;padding:4px 8px;margin-bottom:7px">'
                + '<button class="wgx-nav" data-key="' + gkey + '" data-delta="-1" style="background:#fff;border:1px solid #ccc;border-radius:3px;padding:2px 8px;cursor:pointer;font-size:13px">&#9664;</button>'
                + '<span style="font-size:11px;color:#555;text-align:center;line-height:1.4"><strong>' + (group.idx + 1) + '</strong>&nbsp;/&nbsp;' + total + ' peers<br><span style="color:#5cb85c">' + onlineCount + ' online</span></span>'
                + '<button class="wgx-nav" data-key="' + gkey + '" data-delta="1" style="background:#fff;border:1px solid #ccc;border-radius:3px;padding:2px 8px;cursor:pointer;font-size:13px">&#9654;</button>'
                + '</div>';
        }

        return navBar
            + '<strong style="font-size:13px">' + m.descr + '</strong>' + tagHtml + repBadge
            + '<hr style="margin:5px 0">'
            + '<table style="font-size:11px;width:100%;border-collapse:collapse">'
            + '<tr><td style="color:#777;padding-right:8px;white-space:nowrap">Status</td><td>'    + statusDot + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">Tunnel</td><td>'                      + m.tun + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">Endpoint</td><td><code>'              + m.ep_ip + '</code></td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">Location</td><td>'
                + (m.loc_source === 'gps'
                    ? '<span style="background:#8e44ad;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-right:4px">&#128247; GPS</span>'
                      + (m.gps_age ? '<span style="font-size:10px;color:' + (m.gps_stale ? '#c0392b' : '#999') + '">'
                          + (m.gps_stale ? '&#9888; stale — ' : 'updated ') + m.gps_age + '</span>' : '')
                    : '<span style="background:#777;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;margin-right:4px">IP Est.</span>'
                      + (m.city ? m.city + ', ' : '') + m.country)
                + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">ISP</td><td>'                         + (m.isp || '&mdash;') + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">Handshake</td><td>'                   + m.hs + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">&#8595; Down</td><td style="color:#5cb85c">' + m.dl + '</td></tr>'
            + '<tr><td style="color:#777;white-space:nowrap">&#8593; Up</td><td style="color:#5bc0de">'   + m.ul + '</td></tr>'
            + localNote
            + '</table>';
    }

    /* ---- Place one Leaflet marker per location group ---- */
    var bounds         = [];
    var leafletMarkers = {};

    Object.keys(groups).forEach(function (key) {
        var group      = groups[key];
        var peers      = group.peers;
        var anyOnline  = peers.some(function (p) { return p.online; });
        var anyFlagged = peers.some(function (p) { return p.flags !== ''; });
        var anyLocal   = peers.some(function (p) { return p.is_local === true; });
        var anyGps     = peers.some(function (p) { return p.loc_source === 'gps'; });
        var locSource  = anyGps ? 'gps' : (anyLocal ? 'local' : 'ip');

        var lm = L.marker([group.lat, group.lon], {
            icon: makeIcon(anyOnline, anyFlagged, anyLocal, peers.length, locSource)
        }).addTo(map);

        lm.bindPopup('', { maxWidth: 280, autoPan: true });

        lm.on('click', function () {
            group.idx = 0;
            lm.setPopupContent(buildPopupContent(group));
            lm.openPopup();
        });

        leafletMarkers[key] = lm;
        bounds.push([group.lat, group.lon]);
    });

    /* ---- Nav button handler — delegated on the map container so it survives
           setPopupContent replacing the DOM on each click ---- */
    document.getElementById('wgx-map').addEventListener('click', function (e) {
        var btn = e.target.closest('button.wgx-nav');
        if (!btn) return;
        var key   = btn.getAttribute('data-key');
        var delta = parseInt(btn.getAttribute('data-delta'), 10);
        var grp   = groups[key];
        var lmk   = leafletMarkers[key];
        if (!grp || !lmk) return;
        grp.idx = (grp.idx + delta + grp.peers.length) % grp.peers.length;
        lmk.setPopupContent(buildPopupContent(grp));
    });

    if (bounds.length > 0) {
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 10 });
    }

    /* ---- Legend ---- */
    var legend = L.control({ position: 'bottomright' });
    legend.onAdd = function () {
        var div = L.DomUtil.create('div', 'wgx-map-legend');
        div.innerHTML = '<strong>WG Suite Map</strong><br>'
            + '<span class="wgx-dot-lg" style="background:#8e44ad"></span>GPS Location<br>'
            + '<span class="wgx-dot-lg" style="background:#5cb85c"></span>Online (IP Est.)<br>'
            + '<span class="wgx-dot-lg" style="background:#d9534f"></span>Offline<br>'
            + '<span class="wgx-dot-lg" style="background:#337ab7"></span>Local Network<br>'
            + '<span class="wgx-dot-lg" style="background:#f0ad4e"></span>Flagged IP<br>'
            + '<hr style="margin:4px 0">'
            + '<small style="color:#777">Purple pins = real GPS fix.<br>Number = peers at location.</small>';
        return div;
    };
    legend.addTo(map);

    // Show empty state notice if no markers were placed
    if (bounds.length === 0) {
        document.getElementById('mapEmptyNotice').style.display = 'block';
    }

    // Auto-refresh every 60 seconds
    setInterval(function() { window.location.reload(); }, 60000);
}());
</script>
<?php include("foot.inc"); ?>
