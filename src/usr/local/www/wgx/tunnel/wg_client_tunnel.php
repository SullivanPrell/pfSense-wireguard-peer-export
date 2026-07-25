<?php
// wg_client_tunnel.php
//
// Improvements:
//   - Configuration read from environment variables so the rc.d service can
//     launch this with the correct values per-tunnel without editing source.
//   - All echo output replaced with tun_log() which writes to both stdout
//     and syslog so events appear in pfSense's system log.
//   - Handshake read loop handles empty-string returns from non-blocking socket
//     correctly (usleep rather than dying).
//   - Outer reconnect loop with exponential backoff — when the server closes
//     the connection the tunnel re-establishes automatically.

require_once __DIR__ . '/wg_ws_core.php';

set_time_limit(0);
ob_implicit_flush();

// ---------------------------------------------------------------------------
// Logging — writes to stdout and syslog
// ---------------------------------------------------------------------------
function tun_log(string $level, string $msg): void
{
    $ts      = date('Y-m-d H:i:s');
    $syslog_prio = ($level === 'ERROR') ? LOG_ERR : LOG_NOTICE;
    echo "[{$ts}] [{$level}] {$msg}\n";
    syslog($syslog_prio, "WG Suite tunnel: {$msg}");
}

// ---------------------------------------------------------------------------
// Configuration — loaded from conf.php, then overridden by environment vars
// ---------------------------------------------------------------------------

// Default values
$local_wg_ip        = '127.0.0.1';
$local_wg_port      = 51820;
$remote_server_ip   = '';
$remote_server_port = 443;
$gateway_host       = '';
$ws_path            = '/tunnel';

// Step 1: Load the conf.php file
// Priority: argv[1] tunnel name > auto-detect from directory > skip
$conf_loaded = false;
$script_dir  = __DIR__;

// Try tunnel name from argv (e.g. "tun_wg1" -> wg_ws_tun_wg1.conf.php)
if (!empty($argv[1])) {
    $tun_arg   = preg_replace('/[^a-zA-Z0-9_]/', '', $argv[1]);
    $conf_file = $script_dir . '/wg_ws_' . $tun_arg . '.conf.php';
    if (file_exists($conf_file)) {
        require $conf_file;
        $conf_loaded = true;
        tun_log('INFO', "Loaded config from wg_ws_{$tun_arg}.conf.php");
    }
}

// Auto-detect: find any wg_ws_*.conf.php in the same directory
if (!$conf_loaded) {
    $candidates = glob($script_dir . '/wg_ws_*.conf.php') ?: [];
    if (!empty($candidates)) {
        require $candidates[0];
        $conf_loaded = true;
        tun_log('INFO', "Auto-loaded config from " . basename($candidates[0]));
    }
}

if (!$conf_loaded) {
    tun_log('WARN', "No wg_ws_*.conf.php found — falling back to environment variables");
}

// Step 2: Environment variables override conf.php values (allow manual override)
if (getenv('WGX_LOCAL_WG_IP'))   $local_wg_ip        = getenv('WGX_LOCAL_WG_IP');
if (getenv('WGX_LOCAL_WG_PORT'))  $local_wg_port       = (int)getenv('WGX_LOCAL_WG_PORT');
if (getenv('WGX_REMOTE_IP'))      $remote_server_ip    = getenv('WGX_REMOTE_IP');
if (getenv('WGX_REMOTE_PORT'))    $remote_server_port  = (int)getenv('WGX_REMOTE_PORT');
if (getenv('WGX_GATEWAY_HOST'))   $gateway_host        = getenv('WGX_GATEWAY_HOST');
if (getenv('WGX_WS_PATH'))        $ws_path             = getenv('WGX_WS_PATH');

// Ensure gateway_host falls back to remote_server_ip if not set
if (empty($gateway_host)) $gateway_host = $remote_server_ip;

// Final sanity check — abort clearly if no server IP
if (empty($remote_server_ip)) {
    tun_log('ERROR', "No remote server IP configured. Set WGX_REMOTE_IP or provide a wg_ws_*.conf.php file.");
    exit(1);
}

// ---------------------------------------------------------------------------
// Reconnect loop with exponential backoff
// ---------------------------------------------------------------------------
$backoff     = 5;   // seconds — starts here, doubles each failure, caps at 60
$max_backoff = 60;
$attempt     = 0;

while (true) {
    $attempt++;
    tun_log('INFO', "Connection attempt #{$attempt} to {$remote_server_ip}:{$remote_server_port}");

    // -----------------------------------------------------------------------
    // 1. Create and bind the UDP socket (WireGuard side)
    // -----------------------------------------------------------------------
    $udp_sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if ($udp_sock === false) {
        tun_log('ERROR', 'UDP socket_create failed: ' . socket_strerror(socket_last_error()));
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }
    if (!socket_bind($udp_sock, $local_wg_ip, $local_wg_port)) {
        tun_log('ERROR', 'UDP socket_bind failed: ' . socket_strerror(socket_last_error($udp_sock)));
        socket_close($udp_sock);
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }
    socket_set_nonblock($udp_sock);

    // -----------------------------------------------------------------------
    // 2. TLS stream connection to WebSocket server
    //    We use stream_socket_client (not socket_create) so PHP handles TLS.
    //    The server uses a self-signed cert so we disable peer verification.
    // -----------------------------------------------------------------------
    // Build TLS client context — must match server's TLS 1.2+ requirement
    $tls_client_method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
        $tls_client_method |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
    }
    $ssl_ctx = stream_context_create([
        'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
            'crypto_method'     => $tls_client_method,
            'ciphers'           => 'HIGH:!aNULL:!eNULL:!EXPORT:!RC4',
            'disable_compression' => true,
        ],
    ]);

    // Connect with plain TCP first, then upgrade to TLS manually
    // This gives us control over the TLS handshake and better error messages
    $tls_addr = "tcp://{$remote_server_ip}:{$remote_server_port}";
    $tls_stream = @stream_socket_client(
        $tls_addr, $errno, $errstr, 10,
        STREAM_CLIENT_CONNECT, $ssl_ctx
    );

    if (!$tls_stream) {
        tun_log('ERROR', "TCP connect failed: {$errstr} (errno {$errno})");
        socket_close($udp_sock);
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }

    // Now perform TLS handshake explicitly — matches server's TLS 1.2+ enforcement
    stream_set_blocking($tls_stream, true);
    $tls_client_method2 = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
        $tls_client_method2 |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
    }
    $tls_ok = stream_socket_enable_crypto($tls_stream, true, $tls_client_method2);
    if (!$tls_ok) {
        $err = error_get_last();
        tun_log('ERROR', 'TLS handshake failed: ' . ($err['message'] ?? 'unknown error'));
        fclose($tls_stream);
        socket_close($udp_sock);
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }

    tun_log('INFO', 'TLS connected. Initiating WebSocket handshake...');

    // -----------------------------------------------------------------------
    // 3. WebSocket handshake over TLS stream
    // -----------------------------------------------------------------------
    $handshakeData = generateWebSocketRequestHeaders($gateway_host, $ws_path);
    $clientKey     = $handshakeData['key'];
    $rawRequest    = $handshakeData['raw_request'];

    $written = fwrite($tls_stream, $rawRequest);
    if ($written === false) {
        tun_log('ERROR', 'Handshake write failed');
        fclose($tls_stream);
        socket_close($udp_sock);
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }

    // Read the 101 Switching Protocols response
    $serverResponse = '';
    $deadline       = time() + 10;
    $handshake_ok   = false;
    stream_set_timeout($tls_stream, 1);
    while (time() < $deadline) {
        $chunk = fread($tls_stream, 4096);
        if ($chunk === false || feof($tls_stream)) {
            tun_log('ERROR', 'Connection closed during handshake');
            break;
        }
        $serverResponse .= $chunk;
        if (str_contains($serverResponse, "\r\n\r\n")) {
            $handshake_ok = true;
            break;
        }
        usleep(10000);
    }

    if (!$handshake_ok || !validateServerHandshake($clientKey, $serverResponse)) {
        $preview = substr(trim($serverResponse), 0, 120);
        tun_log('ERROR', "WebSocket handshake failed. Server response: {$preview}");
        fclose($tls_stream);
        socket_close($udp_sock);
        sleep($backoff);
        $backoff = min($backoff * 2, $max_backoff);
        continue;
    }

    tun_log('INFO', 'Handshake validated. Tunnel established. Connect WireGuard now.');
    $backoff = 5; // reset backoff on successful connect

    // Non-blocking for the routing loop
    stream_set_blocking($tls_stream, false);

    // -----------------------------------------------------------------------
    // 4. Routing loop
    //    UDP socket (WireGuard) uses socket_select via a socketpair trick:
    //    we poll the UDP socket separately with a short timeout and use
    //    stream_select for the TLS stream.
    // -----------------------------------------------------------------------
    $last_client_ip   = '';
    $last_client_port = 0;
    $tcp_recv_buffer  = '';
    $frag_buf         = '';
    $frag_opcode      = 0;
    $tunnel_ok        = true;

    while ($tunnel_ok) {
        // Poll TLS stream for incoming data (200ms timeout)
        $read_streams  = [$tls_stream];
        $write_streams = null;
        $except        = null;
        $changed = stream_select($read_streams, $write_streams, $except, 0, 200000);

        // Check for incoming UDP packets from WireGuard (non-blocking)
        $udp_read = [$udp_sock];
        $udp_w    = null;
        $udp_e    = null;
        $udp_ready = socket_select($udp_read, $udp_w, $udp_e, 0, 0);

        if ($changed === false && $udp_ready === false) {
            tun_log('ERROR', 'select error — reconnecting');
            $tunnel_ok = false;
            break;
        }

        // -------------------------------------------------------------------
        // ROUTE A: UDP (WireGuard) → TLS stream (WebSocket server)
        // -------------------------------------------------------------------
        if ($udp_ready > 0 && !empty($udp_read)) {
            $udp_buffer = '';
            $result = socket_recvfrom(
                $udp_sock, $udp_buffer, 65535, 0,
                $last_client_ip, $last_client_port
            );
            if ($result !== false && strlen($udp_buffer) > 0) {
                $frame = createWebSocketFrame($udp_buffer);
                $w = fwrite($tls_stream, $frame);
                if ($w === false) {
                    tun_log('ERROR', 'TLS write error — reconnecting');
                    $tunnel_ok = false;
                    break;
                }
            }
        }

        // -------------------------------------------------------------------
        // ROUTE B: TLS stream (WebSocket server) → UDP (WireGuard)
        // -------------------------------------------------------------------
        if ($changed > 0 && !empty($read_streams)) {
            $chunk = fread($tls_stream, 65535);
            if ($chunk === false || ($chunk === '' && feof($tls_stream))) {
                tun_log('INFO', 'Remote connection closed.');
                $tunnel_ok = false;
                break;
            }
            if ($chunk !== '') {
                $tcp_recv_buffer .= $chunk;
                while (true) {
                    try {
                        $frame = parseWebSocketFrame($tcp_recv_buffer, $frag_buf, $frag_opcode);
                    } catch (\Throwable $e) {
                        tun_log('ERROR', 'Frame parse error: ' . $e->getMessage());
                        $tunnel_ok = false;
                        break 2;
                    }
                    if ($frame === null) break;
                    if ($frame['opcode'] === 0x8) {
                        tun_log('INFO', 'Received WebSocket close frame.');
                        $tunnel_ok = false;
                        break 2;
                    }
                    if ($frame['opcode'] === 0x9) {
                        // Server Ping — reply with Pong to keep the connection alive
                        $pong = createPongFrame($frame['payload']);
                        @fwrite($tls_stream, $pong);
                        continue;
                    }
                    if ($frame['opcode'] === 0xA) {
                        // Pong from server — nothing to do, just keeps us alive
                        continue;
                    }
                    if (in_array($frame['opcode'], [0x0, 0x2], true) && $last_client_port !== 0) {
                        socket_sendto(
                            $udp_sock, $frame['payload'], strlen($frame['payload']),
                            0, $last_client_ip, $last_client_port
                        );
                    }
                }
            }
        }
    }

    // Clean up before reconnecting
    @fclose($tls_stream);
    @socket_close($udp_sock);
    tun_log('INFO', "Tunnel closed. Reconnecting in {$backoff}s...");
    sleep($backoff);
    $backoff = min($backoff * 2, $max_backoff);
}
