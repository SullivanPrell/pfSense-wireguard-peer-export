<?php
/*
 * vpn_wg_checkin.php
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

// =========================================================================
// This page is intentionally standalone — no pfSense auth required.
// Access is protected by a per-peer token stored in pfSense config.
// Phones bookmark: https://<pfsense-ip>/wgx/vpn_wg_checkin.php?token=XXXX
//
// Modes:
//   GET  ?token=X           — show the tracking UI
//   POST (json body)        — receive a GPS fix
//   GET  ?token=X&mode=sw   — serve the Service Worker JS
//   GET  ?token=X&mode=manifest — serve the PWA manifest
// =========================================================================

require_once("config.inc");
require_once("util.inc");

$gps_file = '/var/db/wgx_gps_locations.json';

// ---- Rate limiter — max 1 update per 5 seconds per token ----
function wgx_checkin_rate_limit(string $token): bool {
    $rate_dir  = '/tmp/wgx_checkin_rl';
    if (!is_dir($rate_dir)) {
        @mkdir($rate_dir, 0700, true);
    }
    // Use a hash of the token as the filename so tokens aren't stored in plaintext
    $rate_file = $rate_dir . '/' . hash('sha256', $token);
    $min_gap   = 5; // seconds
    if (file_exists($rate_file) && (time() - filemtime($rate_file)) < $min_gap) {
        return false; // too soon
    }
    touch($rate_file);
    return true;
}

// ---- Peer lookup by token ----
function wgx_find_peer_by_token($token) {
    if (empty($token)) return null;
    $peers = config_get_path('installedpackages/wireguard/peers/item', []);
    if (!is_array($peers)) return null;
    foreach ($peers as $p) {
        if (hash_equals($p['wgx_checkin_token'] ?? '', $token)) {
            return $p;
        }
    }
    return null;
}

// ---- Serve Service Worker ----
if (isset($_GET['mode']) && $_GET['mode'] === 'sw') {
    $token = trim($_GET['token'] ?? '');
    header('Content-Type: application/javascript');
    header('Service-Worker-Allowed: /wgx/');
    // Cache-bust so updated SW is always fresh
    header('Cache-Control: no-cache, no-store');
    $endpoint = '/wgx/vpn_wg_checkin.php';
    $tok_json = json_encode($token);
    $ep_json  = json_encode($endpoint);
    echo "// WG Suite GPS Service Worker\n";
    echo "const TOKEN    = " . $tok_json . ";\n";
    echo "const ENDPOINT = " . $ep_json  . ";\n";
    echo <<<'SWJS'

self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e  => e.waitUntil(self.clients.claim()));

// Periodic Background Sync — fires every ~15 min (Android Chrome, installed PWA)
self.addEventListener('periodicsync', function(event) {
    if (event.tag === 'wgx-location') {
        event.waitUntil(requestLocationFromClients());
    }
});

async function requestLocationFromClients() {
    // Geolocation API is not available inside a Service Worker.
    // Message any open page to send its current location instead.
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    clients.forEach(function(c) { c.postMessage({ type: 'SW_REQUEST_LOCATION' }); });
}

self.addEventListener('message', function(event) {
    if (event.data && event.data.type === 'KEEPALIVE') { /* acknowledged */ }
});
SWJS;
    exit;
}

// ---- Serve PWA Manifest ----
if (isset($_GET['mode']) && $_GET['mode'] === 'manifest') {
    $token = trim($_GET['token'] ?? '');
    $peer  = wgx_find_peer_by_token($token);
    $name  = $peer ? htmlspecialchars($peer['descr'] ?? 'WG Suite', ENT_QUOTES) : 'WG Suite';
    header('Content-Type: application/manifest+json');
    header('Cache-Control: no-cache');
    echo json_encode([
        'name'             => 'WG Suite — ' . strip_tags($name),
        'short_name'       => 'WG GPS',
        'start_url'        => '/wgx/vpn_wg_checkin.php?token=' . urlencode($token),
        'display'          => 'standalone',
        'background_color' => '#1a3a5c',
        'theme_color'      => '#2d6a9f',
        'icons'            => [
            ['src' => '/wgx/qrlogo.png', 'sizes' => '192x192', 'type' => 'image/png'],
        ],
        'permissions'      => ['geolocation'],
    ], JSON_PRETTY_PRINT);
    exit;
}

// ---- Handle GET location update (GPSLogger for Android uses GET) ----
// URL format: ?token=X&lat=%LAT&lon=%LON&acc=%ACC&spd=%SPD&mode=gpslogger
if ($_SERVER['REQUEST_METHOD'] === 'GET' &&
    isset($_GET['lat']) && isset($_GET['lon']) && isset($_GET['token'])) {
    header('Content-Type: application/json');
    $token = trim($_GET['token'] ?? '');
    $peer  = wgx_find_peer_by_token($token);
    if (!$peer) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Invalid token.']);
        exit;
    }
    $lat = filter_var($_GET['lat'] ?? '', FILTER_VALIDATE_FLOAT);
    $lon = filter_var($_GET['lon'] ?? '', FILTER_VALIDATE_FLOAT);
    $acc = filter_var($_GET['acc'] ?? 0,  FILTER_VALIDATE_FLOAT);
    $spd = filter_var($_GET['spd'] ?? 0,  FILTER_VALIDATE_FLOAT);
    if ($lat === false || $lon === false ||
        $lat < -90 || $lat > 90 || $lon < -180 || $lon > 180) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid coordinates.']);
        exit;
    }
    if (!wgx_checkin_rate_limit($token)) {
        http_response_code(429);
        echo json_encode(['success' => false, 'message' => 'Rate limit — please wait before sending another update.']);
        exit;
    }
    $peer_key  = $peer['publickey'];
    $peer_name = $peer['descr'] ?? 'Unknown Peer';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (strpos($client_ip, '::ffff:') === 0) $client_ip = substr($client_ip, 7);
    $gps_data = file_exists($gps_file)
    ? (json_decode(file_get_contents($gps_file), true) ?? []) : [];
    $gps_data[$peer_key] = [
        'lat' => $lat, 'lon' => $lon, 'acc' => $acc ?: null, 'spd' => $spd ?: null,
        'name' => $peer_name, 'client_ip' => $client_ip,
        'updated' => time(), 'mode' => $_GET['mode'] ?? 'gpslogger',
    ];
    file_put_contents($gps_file, json_encode($gps_data, JSON_PRETTY_PRINT), LOCK_EX);
    syslog(LOG_NOTICE, "WG Suite: GPS update (GET) from '{$peer_name}' lat={$lat} lon={$lon}");
    echo json_encode(['success' => true]);
    exit;
    }

// ---- Handle POST: receive GPS fix ----
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');

    $body  = file_get_contents('php://input');
    $data  = $body ? (json_decode($body, true) ?? []) : [];
    // Also accept form-encoded (URLSearchParams)
    if (empty($data)) $data = $_POST;

    $token = trim($data['token'] ?? '');
    $peer  = wgx_find_peer_by_token($token);
    if (!$peer) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Invalid or expired check-in link.']);
        exit;
    }

    $lat = filter_var($data['lat'] ?? '', FILTER_VALIDATE_FLOAT);
    $lon = filter_var($data['lon'] ?? '', FILTER_VALIDATE_FLOAT);
    $acc = filter_var($data['acc'] ?? 0,  FILTER_VALIDATE_FLOAT);
    $spd = filter_var($data['spd'] ?? 0,  FILTER_VALIDATE_FLOAT);

    if ($lat === false || $lon === false ||
        $lat < -90 || $lat > 90 || $lon < -180 || $lon > 180) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid coordinates.']);
        exit;
    }

    $peer_key  = $peer['publickey'];
    $peer_name = $peer['descr'] ?? 'Unknown Peer';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (strpos($client_ip, '::ffff:') === 0) $client_ip = substr($client_ip, 7);

    if (!wgx_checkin_rate_limit($token)) {
        http_response_code(429);
        echo json_encode(['success' => false, 'message' => 'Rate limit — please wait before sending another update.']);
        exit;
    }

    $gps_data = file_exists($gps_file)
    ? (json_decode(file_get_contents($gps_file), true) ?? [])
    : [];

    $gps_data[$peer_key] = [
        'lat'       => $lat,
        'lon'       => $lon,
        'acc'       => $acc ?: null,
        'spd'       => $spd ?: null,
        'name'      => $peer_name,
        'client_ip' => $client_ip,
        'updated'   => time(),
        'mode'      => $data['mode'] ?? 'manual',
    ];

    file_put_contents($gps_file, json_encode($gps_data, JSON_PRETTY_PRINT), LOCK_EX);
    syslog(LOG_NOTICE, "WG Suite: GPS update from '{$peer_name}' ({$client_ip}) lat={$lat} lon={$lon}" . ($acc ? " acc=±{$acc}m" : ''));

    echo json_encode(['success' => true, 'name' => $peer_name, 'lat' => $lat, 'lon' => $lon]);
    exit;
}

// ---- GET: show the tracking UI ----
$token_param       = trim($_GET['token'] ?? '');
$token_peer        = wgx_find_peer_by_token($token_param);
$token_valid       = ($token_peer !== null);
$peer_name_display = $token_valid ? ($token_peer['descr'] ?? 'there') : '';

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#2d6a9f">
<title>WG Suite GPS</title>
<?php if ($token_valid): ?>
<link rel="manifest" href="?token=<?= urlencode($token_param) ?>&mode=manifest">
<?php endif; ?>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(160deg, #1a3a5c 0%, #2d6a9f 55%, #1e8a6e 100%);
    min-height: 100vh;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 24px 16px 40px;
    color: #fff;
}

.card {
    background: rgba(255,255,255,0.11);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.18);
    border-radius: 22px;
    padding: 32px 24px 28px;
    width: 100%;
    max-width: 380px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0,0,0,0.3);
}

.logo { font-size: 48px; line-height: 1; margin-bottom: 6px; }
h1    { font-size: 20px; font-weight: 700; margin-bottom: 2px; }
.subtitle { font-size: 13px; opacity: 0.7; margin-bottom: 22px; }

/* Live tracking pill */
.track-pill {
    display: inline-flex; align-items: center; gap: 8px;
    background: rgba(92,184,92,0.25); border: 1px solid rgba(92,184,92,0.5);
    border-radius: 99px; padding: 6px 14px; font-size: 13px; font-weight: 600;
    margin-bottom: 18px; display: none;
}
.track-pill.active { display: inline-flex; }
.pulse {
    width: 9px; height: 9px; border-radius: 50%;
    background: #5cb85c;
    box-shadow: 0 0 0 0 rgba(92,184,92,0.6);
    animation: pulse 1.6s infinite;
}
@keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(92,184,92,0.6); }
    70%  { box-shadow: 0 0 0 8px rgba(92,184,92,0); }
    100% { box-shadow: 0 0 0 0 rgba(92,184,92,0); }
}

.btn-main {
    width: 100%; padding: 15px;
    background: rgba(255,255,255,0.95); color: #1a3a5c;
    border: none; border-radius: 12px;
    font-size: 16px; font-weight: 700; cursor: pointer;
    transition: transform 0.1s, opacity 0.2s;
    box-shadow: 0 4px 14px rgba(0,0,0,0.2);
    display: flex; align-items: center; justify-content: center; gap: 9px;
    -webkit-tap-highlight-color: transparent;
    margin-bottom: 10px;
}
.btn-main:active  { transform: scale(0.97); }
.btn-main:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.btn-main.stop  { background: rgba(217,83,79,0.9); color: #fff; }

.status { margin: 14px 0; min-height: 52px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px; }
.status-icon   { font-size: 30px; line-height: 1; }
.status-msg    { font-size: 14px; font-weight: 600; }
.status-detail { font-size: 12px; opacity: 0.7; line-height: 1.4; }

.coords {
    margin: 12px 0;
    background: rgba(0,0,0,0.25); border-radius: 10px;
    padding: 10px 14px; font-size: 11.5px;
    font-family: 'SF Mono','Fira Code',monospace; opacity: 0.9;
    display: none; text-align: left; line-height: 1.9;
}

.divider { margin: 20px 0 16px; border: none; border-top: 1px solid rgba(255,255,255,0.15); }

/* Info sections */
.info-box {
    background: rgba(255,255,255,0.07); border-radius: 12px;
    padding: 14px 16px; margin-bottom: 12px; text-align: left;
}
.info-box h3 { font-size: 12px; font-weight: 700; opacity: 0.6; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.info-row { display: flex; align-items: flex-start; gap: 8px; font-size: 12.5px; line-height: 1.5; margin-bottom: 5px; }
.info-row:last-child { margin-bottom: 0; }
.info-dot { margin-top: 3px; width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.dot-green { background: #5cb85c; }
.dot-amber { background: #f0ad4e; }
.dot-grey  { background: rgba(255,255,255,0.35); }

.error-card {
    background: rgba(200,50,50,0.25); border: 1px solid rgba(255,100,100,0.4);
    border-radius: 12px; padding: 20px; font-size: 14px; line-height: 1.6;
}

.badge { display: inline-block; background: rgba(255,255,255,0.15); border-radius: 6px; padding: 2px 7px; font-size: 11px; font-family: monospace; }
</style>
</head>
<body>
<div class="card">

<?php if (!$token_valid): ?>

  <div class="logo">🔒</div>
  <h1>Access Denied</h1>
  <p class="subtitle">Invalid or missing check-in token.</p>
  <div class="error-card">Ask your network admin for the correct check-in link.</div>

<?php else: ?>

  <div class="logo">📡</div>
  <h1>WG Suite</h1>
  <p class="subtitle">GPS Tracker — <?= htmlspecialchars($peer_name_display, ENT_QUOTES) ?></p>

  <div class="track-pill" id="trackPill">
    <div class="pulse"></div>
    <span id="trackPillText">Tracking active</span>
  </div>

  <button class="btn-main" id="startBtn" onclick="startTracking()">
    <span>📍</span> Start Live Tracking
  </button>
  <button class="btn-main stop" id="stopBtn" onclick="stopTracking()" style="display:none">
    <span>⏹</span> Stop Tracking
  </button>

  <div class="status" id="status">
    <div class="status-detail">Tap Start to share your live location.<br>Keep this page open for continuous updates.</div>
  </div>

  <div class="coords" id="coords"></div>

  <hr class="divider">

  <div class="info-box">
    <h3>📶 While this page is open</h3>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Tap <strong>Start Live Tracking</strong> — location sends every 30 s automatically.
      Keep this tab open for continuous updates.</span></div>
    <div class="info-row"><div class="info-dot dot-amber"></div>
      <span>When you close or background the page, updates stop. Use the background methods below for always-on tracking.</span></div>
  </div>

  <div class="info-box" id="androidBox" style="display:none">
    <h3>🤖 Android — Always-On Background (GPSLogger)</h3>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Install <strong>GPSLogger</strong> (free, open source) from the Play Store.</span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Open GPSLogger → ☰ Menu → <strong>Log to custom URL</strong> → enable it.</span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Paste this URL into the <em>URL</em> field (tap to copy):<br>
      <span class="badge" id="gpsloggerUrl" onclick="copyGpsloggerUrl(this)" style="cursor:pointer;word-break:break-all;display:block;margin-top:5px;padding:8px;font-size:10px;line-height:1.6"></span></span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Set <strong>HTTP Method</strong> to <code>GET</code>. Set log interval to your preference (e.g. every 5 min).</span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Back on the main screen, tap <strong>Start Logging</strong>. GPSLogger runs as a persistent background service — it will update the map even when your phone is locked.</span></div>
  </div>

  <div class="info-box" id="iosBox">
    <h3>📱 iPhone — Always-On Background (Shortcuts)</h3>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Open the <strong>Shortcuts</strong> app (built into iOS).</span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Tap <strong>+</strong> to create a new Shortcut. Add these actions in order:<br>
      1. <strong>Get Current Location</strong><br>
      2. <strong>Get Contents of URL</strong> — set to:<br>
      <span class="badge" id="shortcutUrl" style="word-break:break-all;display:block;margin-top:4px;padding:6px;font-size:10px;line-height:1.6"></span>
      Method: <strong>POST</strong> · Request Body: <strong>JSON</strong><br>
      Add these keys:<br>
      <code>token</code> → paste your token<br>
      <code>lat</code> → <em>Current Location → Latitude</em><br>
      <code>lon</code> → <em>Current Location → Longitude</em><br>
      <code>acc</code> → type <code>0</code> (accuracy not available in iOS Shortcuts)<br>
      <code>mode</code> → type <code>ios_shortcut</code>
      </span></div>
    <div class="info-row"><div class="info-dot dot-green"></div>
      <span>Go to the <strong>Automation</strong> tab → <strong>New Automation</strong> → <strong>Time of Day</strong>.<br>
      Set it to repeat every hour. Select your shortcut. Turn off <em>"Ask Before Running"</em> — this makes it run silently in background without any prompt.</span></div>
    <div class="info-row"><div class="info-dot dot-amber"></div>
      <span>iOS will ask for location permission when the automation first runs. Tap <strong>Always Allow</strong>.</span></div>
  </div>

  <p style="font-size:11px; opacity:0.45; margin-top:8px;">Location visible to network admin only. Not shared with any third party.</p>

<?php endif; ?>

</div>

<?php if ($token_valid): ?>
<script>
var TOKEN    = <?= json_encode($token_param) ?>;
var ENDPOINT = <?= json_encode('https://' . $_SERVER['HTTP_HOST'] . '/wgx/vpn_wg_checkin.php') ?>;
var SW_URL   = <?= json_encode('https://' . $_SERVER['HTTP_HOST'] . '/wgx/vpn_wg_checkin.php?token=' . urlencode($token_param) . '&mode=sw') ?>;

var watchId      = null;
var lastLat      = null;
var lastLon      = null;
var lastSendTime = 0;
var MIN_INTERVAL = 30000;   // ms — don't send more often than this
var isTracking   = false;

// ---- Detect platform ----
var isIOS     = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
var isAndroid = /Android/.test(navigator.userAgent);
// Show both on desktop so admin can see both; on phone show the relevant one
if (isIOS || isAndroid) {
    document.getElementById('iosBox').style.display     = isIOS     ? '' : 'none';
    document.getElementById('androidBox').style.display = isAndroid ? '' : 'none';
}

// Build the GPSLogger URL (GET with GPSLogger substitution variables)
var gpsloggerUrl = ENDPOINT
    + '?token=' + encodeURIComponent(TOKEN)
    + '&lat=%LAT&lon=%LON&acc=%ACC&spd=%SPD&mode=gpslogger';
document.getElementById('gpsloggerUrl').textContent = gpsloggerUrl;

// iOS Shortcut posts to the same POST endpoint
document.getElementById('shortcutUrl').textContent  = ENDPOINT;

function copyGpsloggerUrl(el) {
    navigator.clipboard.writeText(gpsloggerUrl).then(function() {
        var orig = el.textContent;
        el.textContent = '✓ Copied!';
        setTimeout(function() { el.textContent = orig; }, 2000);
    }).catch(function() {
        // Fallback: select the text
        var range = document.createRange();
        range.selectNode(el);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
    });
}

// ---- Status helpers ----
function setStatus(icon, msg, detail) {
    document.getElementById('status').innerHTML =
        (icon ? '<div class="status-icon">' + icon + '</div>' : '') +
        '<div class="status-msg">'    + msg    + '</div>' +
        (detail ? '<div class="status-detail">' + detail + '</div>' : '');
}

function updateCoords(lat, lon, acc, spd) {
    var c = document.getElementById('coords');
    c.style.display = 'block';
    c.innerHTML =
        '📍 Lat: ' + lat.toFixed(6) +
        '  Lon: '  + lon.toFixed(6) +
        (acc ? '<br>⭕ Accuracy: ±' + Math.round(acc) + ' m' : '') +
        (spd && spd > 0.5 ? '<br>🚀 Speed: ' + (spd * 3.6).toFixed(1) + ' km/h' : '');
}

// ---- Send a fix to pfSense ----
function sendFix(lat, lon, acc, spd, mode) {
    lastLat      = lat;
    lastLon      = lon;
    lastSendTime = Date.now();

    var payload = JSON.stringify({ token: TOKEN, lat: lat, lon: lon, acc: acc || 0, spd: spd || 0, mode: mode || 'live' });

    fetch(ENDPOINT, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    payload,
        keepalive: true     // survives page unload
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.success) {
            document.getElementById('trackPillText').textContent = 'Updated ' + new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
            setStatus('✅', 'Location sent', 'Next update in ~30 s while this page is open.');
        }
    })
    .catch(function() {
        setStatus('⚠️', 'Send failed', 'Will retry on next position update.');
    });
}

// ---- watchPosition callback ----
function onPosition(pos) {
    var lat = pos.coords.latitude;
    var lon = pos.coords.longitude;
    var acc = pos.coords.accuracy;
    var spd = pos.coords.speed;

    updateCoords(lat, lon, acc, spd);

    var now = Date.now();
    // Send if enough time has passed OR if moved significantly (>50 m)
    var moved = lastLat !== null
        ? Math.abs(lat - lastLat) + Math.abs(lon - lastLon) > 0.0005
        : true;

    if ((now - lastSendTime) >= MIN_INTERVAL || moved) {
        sendFix(lat, lon, acc, spd, 'live');
        setStatus('📡', 'Transmitting…', '');
    } else {
        var secs = Math.round((MIN_INTERVAL - (now - lastSendTime)) / 1000);
        setStatus('📍', 'Location acquired', 'Next send in ' + secs + ' s');
    }
}

function onError(err) {
    var msgs = {
        1: 'Permission denied — please allow location access in your browser settings.',
        2: 'Location unavailable. Try moving near a window.',
        3: 'Location timed out. Retrying…'
    };
    setStatus('❌', 'Location error', msgs[err.code] || err.message);
    // Don't stop tracking on timeout — watchPosition auto-retries
}

// ---- Start / Stop ----
function startTracking() {
    if (!navigator.geolocation) {
        setStatus('❌', 'Not supported', 'This browser does not support GPS.');
        return;
    }

    isTracking = true;
    document.getElementById('startBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display  = '';
    document.getElementById('trackPill').classList.add('active');
    setStatus('⏳', 'Acquiring location…', 'Allow location access if prompted.');

    watchId = navigator.geolocation.watchPosition(
        onPosition, onError,
        { enableHighAccuracy: true, timeout: 20000, maximumAge: 5000 }
    );

    registerServiceWorker();
    preventSleep();
}

function stopTracking() {
    isTracking = false;
    if (watchId !== null) {
        navigator.geolocation.clearWatch(watchId);
        watchId = null;
    }
    document.getElementById('startBtn').style.display = '';
    document.getElementById('stopBtn').style.display  = 'none';
    document.getElementById('trackPill').classList.remove('active');
    document.getElementById('coords').style.display   = 'none';
    setStatus('⏹', 'Tracking stopped', 'Tap Start to resume.');
    cancelSleep();
}

// ---- Service Worker + Periodic Background Sync (Android Chrome) ----
function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;

    navigator.serviceWorker.register(SW_URL, { scope: '/wgx/' })
    .then(function(reg) {
        // Request Periodic Background Sync if available
        if ('periodicSync' in reg) {
            navigator.permissions.query({ name: 'periodic-background-sync' })
            .then(function(status) {
                if (status.state === 'granted') {
                    return reg.periodicSync.register('wgx-location', { minInterval: 15 * 60 * 1000 });
                }
            })
            .catch(function() { /* not supported */ });
        }

        // Listen for SW messages asking for a location update
        navigator.serviceWorker.addEventListener('message', function(event) {
            if (event.data && event.data.type === 'SW_REQUEST_LOCATION' && lastLat !== null) {
                sendFix(lastLat, lastLon, null, null, 'background_sync');
            }
        });
    })
    .catch(function(err) {
        // SW registration failed — not critical, live tracking still works
        console.warn('SW registration failed:', err);
    });
}

// ---- Screen wake lock — keep screen/page alive on Android ----
var wakeLock = null;

async function preventSleep() {
    if ('wakeLock' in navigator) {
        try {
            wakeLock = await navigator.wakeLock.request('screen');
        } catch(e) { /* not available */ }
    }
}

function cancelSleep() {
    if (wakeLock) { wakeLock.release(); wakeLock = null; }
}

// Re-acquire wake lock after tab becomes visible again
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible' && isTracking && !wakeLock) {
        preventSleep();
    }
});
</script>
<?php endif; ?>
</body>
</html>
