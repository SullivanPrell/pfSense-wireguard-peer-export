<?php
declare(strict_types=1);
// =============================================================================
// wg_ws_server.php
// WebSocket-to-WireGuard bridge — runs ON pfSense, listens on TCP 443 (TLS),
// accepts WebSocket upgrade requests, then bidirectionally relays binary frames
// to/from the local WireGuard UDP socket on 127.0.0.1:51820.
//
// Usage:
//   php /usr/local/www/wgx/tunnel/wg_ws_server.php
//
// Start at boot via rc.d — see wg_ws_server_rc.sh in the same directory.
//
// Requirements:
//   - Port 443 must be free (move pfSense web UI to 8443 first)
//   - A PEM file containing cert + private key (see Step 2 in the docs)
//   - wg_ws_core.php in the same directory
// =============================================================================

require_once __DIR__ . '/wg_ws_core.php';

set_time_limit(0);
ob_implicit_flush();

// ---------------------------------------------------------------------------
// Configuration — edit these or override via environment variables
// ---------------------------------------------------------------------------
$bind_ip        = '0.0.0.0';
$bind_port      = 443;
$ws_path        = '/tunnel';
$wg_ip          = '127.0.0.1';
$wg_port        = 51820;
$cert_pem       = '/usr/local/etc/wg_ws/server.pem'; // Secure path — not /tmp
$max_clients    = 50;
$max_per_ip     = 3;     // Per-IP connection cap — prevents slot exhaustion DoS
$ping_interval  = 25;
$idle_timeout   = 120;
$auth_token     = '';    // Set via WG_WS_TOKEN — empty disables auth
$header_max     = 8192;  // Max HTTP upgrade header size — prevents header-flood DoS

if (getenv('WG_WS_CERT'))      $cert_pem      = getenv('WG_WS_CERT');
if (getenv('WG_WS_PORT'))      $bind_port     = (int)getenv('WG_WS_PORT');
if (getenv('WG_WS_PATH'))      $ws_path       = getenv('WG_WS_PATH');
if (getenv('WG_WG_PORT'))      $wg_port       = (int)getenv('WG_WG_PORT');
if (getenv('WG_WS_TOKEN'))     $auth_token    = getenv('WG_WS_TOKEN');
if (getenv('WG_WS_MAX_PER_IP'))$max_per_ip    = (int)getenv('WG_WS_MAX_PER_IP');
if (getenv('WG_WS_PING'))      $ping_interval = (int)getenv('WG_WS_PING');
if (getenv('WG_WS_IDLE'))      $idle_timeout  = (int)getenv('WG_WS_IDLE');

// ---------------------------------------------------------------------------
// Preflight checks
// ---------------------------------------------------------------------------
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('This script must be run from the command line.');
}

if (!file_exists($cert_pem) || !is_readable($cert_pem)) {
    fwrite(STDERR, "ERROR: Certificate file not found or not readable: {$cert_pem}\n");
    fwrite(STDERR, "       Run the cert-export command from Step 2 first.\n");
    exit(1);
}

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------
function srv_log(string $level, string $msg, string $client = ''): void
{
    $ts     = date('Y-m-d H:i:s');
    $prefix = $client ? "[{$client}] " : '';
    $line   = "[{$ts}] [{$level}] {$prefix}{$msg}";
    echo $line . "\n";
    syslog(LOG_NOTICE, "WG WS Server: {$msg}" . ($client ? " [{$client}]" : ''));
}

function srv_info(string $msg, string $c = ''): void { srv_log('INFO',  $msg, $c); }
function srv_warn(string $msg, string $c = ''): void { srv_log('WARN',  $msg, $c); }
function srv_err(string $msg,  string $c = ''): void { srv_log('ERROR', $msg, $c); }

// ---------------------------------------------------------------------------
// Per-client state
// ---------------------------------------------------------------------------
// $clients[id] = [
//   'stream'         => resource,   TLS stream socket
//   'addr'           => string,     remote IP:port
//   'udp'            => resource,   UDP socket to WireGuard for this client
//   'tcp_buf'        => string,     inbound TLS receive buffer
//   'udp_buf'        => string,     inbound UDP receive buffer (single datagram)
//   'frag_buf'       => string,     WS fragmentation reassembly buffer
//   'frag_opcode'    => int,
//   'last_activity'  => int,        unix timestamp of last frame in either direction
//   'last_ping'      => int,        unix timestamp of last ping sent
//   'handshaked'     => bool,       HTTP upgrade complete
// ]
$clients   = [];
$next_id   = 1;
$ip_counts = []; // per-IP connection tracking for $max_per_ip cap

// ---------------------------------------------------------------------------
// TLS server socket
// ---------------------------------------------------------------------------
// Bind on tcp:// so stream_socket_accept() returns a plain TCP stream.
// TLS is negotiated explicitly in do_handshake() via
// stream_socket_enable_crypto() — avoids a double TLS handshake
// that would occur if ssl:// were used (ssl:// auto-negotiates on accept,
// then do_handshake would attempt a second negotiation causing broken pipe).
$ctx = stream_context_create([
    'ssl' => [
        'local_cert'          => $cert_pem,
        'local_pk'            => $cert_pem,
        'verify_peer'         => false,
        'allow_self_signed'   => true,
        'ciphers'             => 'HIGH:!aNULL:!eNULL:!EXPORT:!RC4',
        'disable_compression' => true,
    ],
]);

$listen_addr = "tcp://{$bind_ip}:{$bind_port}";
$server = stream_socket_server($listen_addr, $errno, $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);

if (!$server) {
    fwrite(STDERR, "ERROR: Cannot bind {$listen_addr}: {$errstr} (errno {$errno})\n");
    if ($errno === 13) {
        fwrite(STDERR, "       Permission denied — run as root, or use authbind.\n");
    }
    if ($errno === 98 || $errno === 48) {
        fwrite(STDERR, "       Address in use — is the web UI still on port {$bind_port}?\n");
    }
    exit(1);
}

stream_set_blocking($server, false);
srv_info("Listening on {$listen_addr} — WireGuard target {$wg_ip}:{$wg_port}");

// ---------------------------------------------------------------------------
// Helper: perform TLS + WebSocket handshake on a newly accepted stream
// Returns true on success, false if the client should be dropped.
// ---------------------------------------------------------------------------
function do_handshake($stream, string $addr, string $ws_path, string $auth_token, int $header_max): bool
{
    // Complete TLS — enforce TLS 1.2 minimum, reject 1.0/1.1
    stream_set_blocking($stream, true);
    $tls_method = defined('STREAM_CRYPTO_METHOD_TLSv1_2_SERVER')
    ? (STREAM_CRYPTO_METHOD_TLSv1_2_SERVER | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER') ? STREAM_CRYPTO_METHOD_TLSv1_3_SERVER : 0))
    : STREAM_CRYPTO_METHOD_TLS_SERVER;
    $ok = stream_socket_enable_crypto($stream, true, $tls_method);

    if (!$ok) {
        srv_warn("TLS handshake failed", $addr);
        stream_set_blocking($stream, false);
        return false;
    }

    // Read the HTTP Upgrade request with an 8KB cap to prevent header-flood DoS
    $deadline   = time() + 5;
    $req        = '';
    stream_set_blocking($stream, true);
    while (time() < $deadline) {
        $chunk = fread($stream, 4096);
        if ($chunk === false || ($chunk === '' && feof($stream))) break;
        $req .= $chunk;
        if (strlen($req) > $header_max) {
            fwrite($stream, "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
            stream_set_blocking($stream, false);
            return false;
        }
        if (str_contains($req, "\r\n\r\n")) break;
    }
    stream_set_blocking($stream, false);

    if (empty($req)) {
        srv_warn("No HTTP request received", $addr);
        return false;
    }

    $first_line = strtok($req, "\r\n");
    if (!preg_match('~^GET\s+(\S+)\s+HTTP/1\.[01]$~i', $first_line, $m)) {
        srv_warn("Bad HTTP request line: {$first_line}", $addr);
        fwrite($stream, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        return false;
    }

    if ($m[1] !== $ws_path) {
        fwrite($stream, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
        return false;
    }

    if (!preg_match('~Upgrade:\s*websocket~i', $req)) {
        fwrite($stream, "HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n");
        return false;
    }

    // Auth token check — reject with 404 (not 401) to avoid revealing auth exists
    if ($auth_token !== '') {
        $provided = '';
        if (preg_match('~Sec-WebSocket-Protocol:\s*wg-token-([^\r\n]+)~i', $req, $tm)) {
            $provided = trim($tm[1]);
        }
        if (!hash_equals($auth_token, $provided)) {
            srv_warn("Invalid or missing auth token", $addr);
            fwrite($stream, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
            return false;
        }
    }

    if (!preg_match('~Sec-WebSocket-Key:\s*([^\r\n]+)~i', $req, $km)) {
        fwrite($stream, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
        return false;
    }

    $accept = base64_encode(sha1(trim($km[1]) . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));

    fwrite($stream,
           "HTTP/1.1 101 Switching Protocols\r\n" .
           "Upgrade: websocket\r\n" .
           "Connection: Upgrade\r\n" .
           "Sec-WebSocket-Accept: {$accept}\r\n\r\n"
    );
    srv_info("WebSocket handshake complete" . ($auth_token ? " (authenticated)" : ""), $addr);
    return true;
}

// ---------------------------------------------------------------------------
// Helper: write a complete WebSocket frame to a TLS stream, handling partial
// writes by retrying until all bytes are sent or the stream errors.
// ---------------------------------------------------------------------------
function ws_write_all($stream, string $frame): bool
{
    $total  = strlen($frame);
    $offset = 0;
    while ($offset < $total) {
        $written = fwrite($stream, substr($frame, $offset));
        if ($written === false || $written === 0) return false;
        $offset += $written;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Helper: send a WebSocket server Close frame (unmasked — server→client).
// Server-to-client frames must NOT be masked per RFC 6455 §5.1.
// ---------------------------------------------------------------------------
function send_server_close($stream, int $code = 1000, string $reason = ''): void
{
    $body  = pack('n', $code) . substr($reason, 0, 123);
    $frame = chr(0x88) . chr(strlen($body)) . $body;  // FIN+close, unmasked
    @fwrite($stream, $frame);
}

// ---------------------------------------------------------------------------
// Helper: send an unmasked server Ping frame
// ---------------------------------------------------------------------------
function send_server_ping($stream): void
{
    // FIN=1, opcode=0x9 (Ping), no mask, zero payload
    @fwrite($stream, chr(0x89) . chr(0x00));
}

// ---------------------------------------------------------------------------
// Helper: build an unmasked server binary data frame (server→client)
// Server frames are NOT masked (RFC 6455 §5.1)
// ---------------------------------------------------------------------------
function build_server_frame(string $payload): string
{
    $len = strlen($payload);
    if ($len <= 125) {
        return chr(0x82) . chr($len) . $payload;
    }
    if ($len <= 65535) {
        return chr(0x82) . chr(126) . pack('n', $len) . $payload;
    }
    return chr(0x82) . chr(127) . pack('J', $len) . $payload;
}

// ---------------------------------------------------------------------------
// Main event loop
// ---------------------------------------------------------------------------
$running       = true;
$start_time    = time();
$last_stats_ts = time();
$bytes_relayed = 0;

// Handle SIGTERM / SIGINT cleanly
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, function() use (&$running) { $running = false; });
    pcntl_signal(SIGINT,  function() use (&$running) { $running = false; });
}

srv_info("Server ready. Waiting for connections...");

while ($running) {

    if (function_exists('pcntl_signal_dispatch')) {
        pcntl_signal_dispatch();
    }

    // -----------------------------------------------------------------------
    // Build the read set for stream_select:
    //   - the listening server socket (new connections)
    //   - each client's TLS stream (inbound WS frames)
    //   - each client's UDP socket (inbound WireGuard packets)
    // -----------------------------------------------------------------------
    // Build the read set, skipping any client whose sockets have gone invalid
    $read = [$server];
    foreach ($clients as $id => $c) {
        if (is_resource($c['stream']) && is_resource($c['udp'])) {
            $read[] = $c['stream'];
            $read[] = $c['udp'];
        }
    }

    $write  = null;
    $except = null;
    // Suppress the EINTR warning — pcntl signal delivery interrupts select harmlessly
    $changed = @stream_select($read, $write, $except, 0, 200000);

    if ($changed === false) {
        // EINTR from signal delivery is normal; just loop again.
        // Only treat as fatal if we're actually shutting down.
        if (!$running) break;
        usleep(20000);
        continue;
    }

    $now = time();

    // Periodic stats log every 60 seconds
    if (($now - $last_stats_ts) >= 60) {
        $uptime = $now - $start_time;
        srv_info(sprintf(
            'Stats — clients: %d, uptime: %ds, bytes relayed: %s',
            count($clients),
                         $uptime,
                         number_format($bytes_relayed)
        ));
        $last_stats_ts = $now;
    }

    // -----------------------------------------------------------------------
    // Accept new connections
    // -----------------------------------------------------------------------
    if (in_array($server, $read, true)) {
        $new_stream = stream_socket_accept($server, 0, $peer_addr);
        if ($new_stream) {
            // Correctly handles both IPv4 (1.2.3.4:port) and IPv6 ([::1]:port)
            $last_colon = strrpos($peer_addr, ':');
            $src_ip     = $last_colon !== false
            ? trim(substr($peer_addr, 0, $last_colon), '[]')
            : $peer_addr;
            $ip_count = $ip_counts[$src_ip] ?? 0;
            if (count($clients) >= $max_clients) {
                srv_warn("Max clients reached ({$max_clients}) — rejecting {$peer_addr}");
                fclose($new_stream);
            } elseif ($ip_count >= $max_per_ip) {
                srv_warn("Per-IP limit ({$max_per_ip}) reached for {$src_ip} — rejecting");
                fclose($new_stream);
            } else {
                if (do_handshake($new_stream, $peer_addr, $ws_path, $auth_token, $header_max)) {
                    // Create a dedicated UDP socket for this client's WireGuard traffic
                    $udp = stream_socket_client("udp://{$wg_ip}:{$wg_port}",
                        $ue, $us, 1);
                    if (!$udp) {
                        srv_err("Cannot open UDP socket to WireGuard: {$us}", $peer_addr);
                        send_server_close($new_stream, 1011, 'upstream unavailable');
                        fclose($new_stream);
                    } else {
                        stream_set_blocking($new_stream, false);
                        stream_set_blocking($udp, false);
                        // 5-second write timeout — stalled clients won't block the loop
                        stream_set_timeout($new_stream, 5);
                        $id = $next_id++;
                        $clients[$id] = [
                            'stream'        => $new_stream,
                            'addr'          => $peer_addr,
                            'src_ip'        => $src_ip,
                            'udp'           => $udp,
                            'tcp_buf'       => '',
                            'frag_buf'      => '',
                            'frag_opcode'   => 0,
                            'last_activity' => $now,
                            'last_ping'     => $now,
                            'handshaked'    => true,
                        ];
                        $ip_counts[$src_ip] = $ip_count + 1;
                        srv_info("Client connected (id={$id}, ip_conns=" . ($ip_count+1) . ", total=" . count($clients) . ")", $peer_addr);
                    }
                } else {
                    fclose($new_stream);
                }
                } // end else (do_handshake branch)
        } // end if ($new_stream)
    } // end if (in_array($server, $read))

    // -----------------------------------------------------------------------
    // Per-client I/O
    // -----------------------------------------------------------------------
    foreach ($clients as $id => &$client) {

        $drop   = false;
        $reason = '';

        // -------------------------------------------------------------------
        // ROUTE A: Inbound from client (TLS → WebSocket frame → UDP/WireGuard)
        // -------------------------------------------------------------------
        if (in_array($client['stream'], $read, true)) {
            $chunk = fread($client['stream'], 65535);

            if ($chunk === false || ($chunk === '' && feof($client['stream']))) {
                $drop = true; $reason = 'TCP connection closed by client';
            } else {
                $client['tcp_buf']       .= $chunk;
                $client['last_activity']  = $now;

                // [SEC-2] Hard cap on receive buffer
                if (strlen($client['tcp_buf']) > MAX_RECV_BUFFER) {
                    srv_warn("Receive buffer overflow — dropping client", $client['addr']);
                    send_server_close($client['stream'], 1009, 'message too big');
                    $drop = true; $reason = 'recv buffer overflow';
                }

                // Parse all complete frames from the buffer
                while (!$drop) {
                    try {
                        $frame = parseWebSocketFrame(
                            $client['tcp_buf'],
                            $client['frag_buf'],
                            $client['frag_opcode']
                        );
                    } catch (\OverflowException $e) {
                        srv_warn("Frame too large: " . $e->getMessage(), $client['addr']);
                        send_server_close($client['stream'], 1009, 'message too big');
                        $drop = true; $reason = 'oversized frame';
                        break;
                    } catch (\UnexpectedValueException $e) {
                        srv_warn("Protocol error: " . $e->getMessage(), $client['addr']);
                        send_server_close($client['stream'], 1002, 'protocol error');
                        $drop = true; $reason = 'protocol error';
                        break;
                    }

                    if ($frame === null) break; // No complete frame yet

                    switch ($frame['opcode']) {

                        case 0x8: // Close — echo and drop
                            send_server_close($client['stream'], 1000, 'normal closure');
                            $drop = true; $reason = 'client sent Close frame';
                            break 2;

                        case 0x9: // Ping — reply with Pong (unmasked, server→client)
                            $pong = chr(0x8A) . chr(strlen($frame['payload'])) . $frame['payload'];
                            ws_write_all($client['stream'], $pong);
                            break;

                        case 0xA: // Pong — update activity timestamp
                            $client['last_activity'] = $now;
                            break;

                        case 0x2: // Binary — WireGuard packet, forward to UDP
                        case 0x0: // Continuation (already reassembled by parseWebSocketFrame)
                            if (!empty($frame['payload'])) {
                                $written = fwrite($client['udp'], $frame['payload']);
                                if ($written === false) {
                                    srv_warn("UDP write to WireGuard failed", $client['addr']);
                                } else {
                                    $bytes_relayed += strlen($frame['payload']);
                                }
                            }
                            break;

                        default:
                            srv_warn(
                                sprintf("Unknown opcode 0x%02X — ignoring", $frame['opcode']),
                                $client['addr']
                            );
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // ROUTE B: Inbound from WireGuard (UDP → WebSocket frame → TLS client)
        // -------------------------------------------------------------------
        if (!$drop && is_resource($client['udp']) && in_array($client['udp'], $read, true)) {
            $dgram = @fread($client['udp'], 65535);
            if ($dgram === false) {
                // ICMP port-unreachable can surface as a read error on a connected
                // UDP socket. Don't drop the client — WireGuard may just not have
                // been ready. Reopen the UDP socket so the next packet works.
                @fclose($client['udp']);
                $reudp = @stream_socket_client("udp://{$wg_ip}:{$wg_port}", $ue, $us, 1);
                if ($reudp) {
                    stream_set_blocking($reudp, false);
                    $client['udp'] = $reudp;
                }
            } elseif ($dgram !== '') {
                $client['last_activity'] = $now;
                $bytes_relayed += strlen($dgram);
                $frame = build_server_frame($dgram);
                if (!ws_write_all($client['stream'], $frame)) {
                    $drop = true; $reason = 'TLS write error (WireGuard→client)';
                }
            }
        }

        // -------------------------------------------------------------------
        // Keepalive: send a Ping if the client has been quiet for $ping_interval
        // -------------------------------------------------------------------
        if (!$drop && ($now - $client['last_ping']) >= $ping_interval) {
            send_server_ping($client['stream']);
            $client['last_ping'] = $now;
        }

        // -------------------------------------------------------------------
        // Idle timeout: drop clients that haven't responded to pings
        // -------------------------------------------------------------------
        if (!$drop && ($now - $client['last_activity']) >= $idle_timeout) {
            srv_warn("Idle timeout ({$idle_timeout}s) — closing", $client['addr']);
            send_server_close($client['stream'], 1001, 'going away');
            $drop = true; $reason = 'idle timeout';
        }

        // -------------------------------------------------------------------
        // Clean up dropped client
        // -------------------------------------------------------------------
        if ($drop) {
            if ($reason) {
                srv_info("Dropping client: {$reason}", $client['addr']);
            }
            @fclose($client['stream']);
            @fclose($client['udp']);
            $cip = $client['src_ip'] ?? '';
            if ($cip !== '' && isset($ip_counts[$cip])) {
                $ip_counts[$cip]--;
                if ($ip_counts[$cip] <= 0) unset($ip_counts[$cip]);
            }
            unset($clients[$id]);
        }
    }
    unset($client); // Release the by-reference loop variable
}

// ---------------------------------------------------------------------------
// Shutdown — close all clients cleanly
// ---------------------------------------------------------------------------
srv_info("Shutting down — closing " . count($clients) . " client(s)...");
foreach ($clients as $id => $c) {
    send_server_close($c['stream'], 1001, 'server shutting down');
    @fclose($c['stream']);
    @fclose($c['udp']);
}
fclose($server);
srv_info("Server stopped.");
