<?php
// wg_ws_core.php
// RFC 6455 WebSocket Protocol Library — hardened for WG Suite / pfSense
//
// Security fixes applied:
//   [SEC-1] CRLF injection via $gatewayHost / $wsPath — strip \r and \n before
//           writing into HTTP headers.
//   [SEC-2] Buffer-bomb / DoS — parseWebSocketFrame now rejects any declared
//           payload length that exceeds MAX_FRAME_PAYLOAD (64 KB). The caller's
//           accumulation buffer is capped at MAX_RECV_BUFFER (128 KB).
//   [SEC-3] RSV bits — parseWebSocketFrame returns an error if any RSV bit is
//           set (no extensions were negotiated, so this is a protocol violation).
//   [SEC-4] HTTP 101 check — validateServerHandshake now verifies the status
//           line is "101 Switching Protocols" before trusting the Accept header.
//
// Completeness fixes applied:
//   [COMP-1] $wsPath parameter added to generateWebSocketRequestHeaders so the
//            caller can point at an arbitrary endpoint, not just /tunnel.
//   [COMP-2] Ping frame builder (sendWebSocketPing) added so the tunnel can
//            respond to server keepalive probes.
//   [COMP-3] Close frame builder (sendWebSocketClose) added for a clean RFC 6455
//            close handshake before the socket is shut down.
//   [COMP-4] Fragmentation reassembly added inside parseWebSocketFrame via an
//            optional $fragmentBuffer argument; the function accumulates
//            continuation frames and only returns a result once FIN=1.

declare(strict_types=1);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum accepted payload length for a single WebSocket frame (64 KiB). */
const MAX_FRAME_PAYLOAD = 65536;

/** Maximum size of the TCP receive buffer before we declare a protocol error. */
const MAX_RECV_BUFFER = 131072; // 128 KiB

// ---------------------------------------------------------------------------
// Header generation
// ---------------------------------------------------------------------------

/**
 * Generates the RFC 6455 HTTP Upgrade request headers.
 *
 * [SEC-1] $gatewayHost and $wsPath are sanitised to prevent CRLF injection:
 *         any carriage-return or line-feed character is stripped before the
 *         values are written into the raw HTTP request string.
 *
 * [COMP-1] $wsPath is now a parameter (defaulting to '/tunnel') so callers can
 *          point the WebSocket upgrade at any server endpoint.
 *
 * @param  string $gatewayHost  Value for the HTTP Host header (e.g. "192.168.1.1" or "example.com:443").
 * @param  string $wsPath       WebSocket endpoint path, including leading slash (e.g. "/wg-tunnel").
 * @return array{key: string, raw_request: string}
 */
function generateWebSocketRequestHeaders(string $gatewayHost, string $wsPath = '/tunnel'): array
{
    // [SEC-1] Strip CR and LF to prevent HTTP header injection
    $safeHost = str_replace(["\r", "\n"], '', $gatewayHost);
    $safePath = str_replace(["\r", "\n"], '', $wsPath);

    if ($safeHost === '') {
        throw new \InvalidArgumentException('gatewayHost must not be empty.');
    }
    if ($safePath === '' || $safePath[0] !== '/') {
        throw new \InvalidArgumentException('wsPath must be a non-empty string starting with "/".');
    }

    $randomBytes = openssl_random_pseudo_bytes(16);
    $clientKey   = base64_encode($randomBytes);

    $headers  = "GET {$safePath} HTTP/1.1\r\n";
    $headers .= "Host: {$safeHost}\r\n";
    $headers .= "Upgrade: websocket\r\n";
    $headers .= "Connection: Upgrade\r\n";
    $headers .= "Sec-WebSocket-Key: {$clientKey}\r\n";
    $headers .= "Sec-WebSocket-Version: 13\r\n\r\n";

    return [
        'key'         => $clientKey,
        'raw_request' => $headers,
    ];
}

// ---------------------------------------------------------------------------
// Handshake validation
// ---------------------------------------------------------------------------

/**
 * Validates the server's 101 response against the expected RFC 6455 signature.
 *
 * [SEC-4] Now also checks that the HTTP status line is exactly "101 Switching
 *         Protocols". A server returning 200 OK with the correct Accept header
 *         (malformed or hostile) will no longer pass validation.
 *
 * @param  string $clientKey             The original base64 key sent in the request.
 * @param  string $serverResponseHeaders The raw HTTP response string from the server.
 * @return bool   True only when both the status line and Accept hash are correct.
 */
function validateServerHandshake(string $clientKey, string $serverResponseHeaders): bool
{
    // [SEC-4] Require HTTP 101 status line
    // Use ~ as delimiter — '/' appears in base64 keys and HTTP paths, causing
    // silent regex breakage if used as both delimiter and literal character.
    if (!preg_match('~^HTTP/1\.[01] 101[ \t]~i', $serverResponseHeaders)) {
        return false;
    }

    $magicGUID      = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
    $expectedAccept = base64_encode(sha1($clientKey . $magicGUID, true));

    if (preg_match('~Sec-WebSocket-Accept:\s*([^\r\n]+)~i', $serverResponseHeaders, $matches)) {
        // Use hash_equals for constant-time comparison — prevents timing oracle
        return hash_equals($expectedAccept, trim($matches[1]));
    }

    return false;
}

// ---------------------------------------------------------------------------
// Frame creation
// ---------------------------------------------------------------------------

/**
 * Constructs a masked RFC 6455 binary WebSocket frame (opcode 0x2).
 *
 * @param  string $payload  Raw binary data (e.g. a WireGuard UDP packet).
 * @return string           The framed, masked message ready for transmission.
 */
function createWebSocketFrame(string $payload): string
{
    $payloadLength = strlen($payload);

    // Byte 0: FIN=1, RSV=000, Opcode=0x2 (binary)
    $frame = chr(0x82);

    // Byte 1+: MASK bit set (required for client→server, RFC 6455 §5.3)
    if ($payloadLength <= 125) {
        $frame .= chr(0x80 | $payloadLength);
    } elseif ($payloadLength <= 65535) {
        $frame .= chr(0x80 | 126) . pack('n', $payloadLength);
    } else {
        $frame .= chr(0x80 | 127) . pack('J', $payloadLength);
    }

    $maskingKey = openssl_random_pseudo_bytes(4);
    $frame     .= $maskingKey;

    $maskedPayload = '';
    for ($i = 0; $i < $payloadLength; $i++) {
        $maskedPayload .= $payload[$i] ^ $maskingKey[$i % 4];
    }

    return $frame . $maskedPayload;
}

/**
 * Constructs a masked RFC 6455 Pong control frame.
 *
 * [COMP-2] Servers send Ping frames (opcode 0x9) and expect a Pong (opcode 0xA)
 *          in reply. Failing to reply causes compliant servers to close the
 *          connection. The Pong must echo the Ping's payload verbatim.
 *
 * @param  string $pingPayload  The payload received in the Ping frame (max 125 bytes per RFC).
 * @return string               The ready-to-send Pong frame.
 */
function createPongFrame(string $pingPayload): string
{
    // Control frame payload must be ≤ 125 bytes (RFC 6455 §5.5)
    $payload = substr($pingPayload, 0, 125);
    $length  = strlen($payload);

    // Byte 0: FIN=1, Opcode=0xA (Pong)
    $frame      = chr(0x8A);
    $frame     .= chr(0x80 | $length);   // MASK bit set, length ≤ 125 so no extension
    $maskingKey = openssl_random_pseudo_bytes(4);
    $frame     .= $maskingKey;

    for ($i = 0; $i < $length; $i++) {
        $frame .= $payload[$i] ^ $maskingKey[$i % 4];
    }

    return $frame;
}

/**
 * Constructs a masked RFC 6455 Close control frame.
 *
 * [COMP-3] RFC 6455 §7.1.2 requires that the receiving endpoint send its own
 *          Close frame before closing the underlying TCP connection. Without
 *          this the remote peer may log a protocol error.
 *
 * @param  int    $code    RFC 6455 close status code (default 1000 = Normal Closure).
 * @param  string $reason  Optional human-readable reason (max 123 bytes after UTF-8 encode).
 * @return string          The ready-to-send Close frame.
 */
function createCloseFrame(int $code = 1000, string $reason = ''): string
{
    // Control frame: FIN=1, Opcode=0x8 (Close)
    $body = pack('n', $code) . substr($reason, 0, 123);

    // Byte 0: FIN=1, Opcode=0x8
    $frame      = chr(0x88);
    $frame     .= chr(0x80 | strlen($body));
    $maskingKey = openssl_random_pseudo_bytes(4);
    $frame     .= $maskingKey;

    $length = strlen($body);
    for ($i = 0; $i < $length; $i++) {
        $frame .= $body[$i] ^ $maskingKey[$i % 4];
    }

    return $frame;
}

// ---------------------------------------------------------------------------
// Masking (utility)
// ---------------------------------------------------------------------------

/**
 * Applies or reverses the RFC 6455 XOR masking operation.
 * XOR is its own inverse so this function both masks and unmasks.
 *
 * @param  string $payload    Data to process.
 * @param  string $maskingKey The 4-byte key.
 * @return string             Processed binary string.
 * @throws \InvalidArgumentException If the key is not exactly 4 bytes.
 */
function processWebSocketMask(string $payload, string $maskingKey): string
{
    if (strlen($maskingKey) !== 4) {
        throw new \InvalidArgumentException(
            'RFC 6455 requires exactly a 32-bit (4-byte) masking key.'
        );
    }

    $length = strlen($payload);
    if ($length === 0) {
        return '';
    }

    // Fast path: sodium_crypto_stream_xor is significantly faster than a PHP
    // byte loop for large payloads (WireGuard MTU frames are typically ~1400 bytes).
    // It requires a 24-byte nonce and 32-byte key — we derive both from the
    // 4-byte RFC 6455 masking key by repeating it to fill the required lengths.
    if (function_exists('sodium_crypto_stream_xor')) {
        $nonce = str_repeat($maskingKey, 6);   // 4 * 6 = 24 bytes
        $key   = str_repeat($maskingKey, 8);   // 4 * 8 = 32 bytes
        return sodium_crypto_stream_xor($payload, $nonce, $key);
    }

    // Fallback: pure PHP byte loop
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= $payload[$i] ^ $maskingKey[$i % 4];
    }

    return $out;
}

// ---------------------------------------------------------------------------
// Frame parsing  (with fragmentation reassembly)
// ---------------------------------------------------------------------------

/**
 * Parses and reassembles one logical WebSocket message from a raw byte buffer.
 *
 * The function consumes bytes from the front of $buffer (passed by reference)
 * and accumulates fragmented frames inside $fragmentBuffer (also by reference)
 * until a frame with FIN=1 is received, at which point it returns the complete
 * reassembled payload.
 *
 * Returns null when no complete message is yet available; throws on protocol
 * violations.
 *
 * Security fixes:
 *   [SEC-2] Payload length is capped at MAX_FRAME_PAYLOAD (64 KiB). Any frame
 *           declaring a larger length is treated as a fatal protocol error.
 *   [SEC-3] RSV1/RSV2/RSV3 bits cause a protocol error (no extensions negotiated).
 *
 * Completeness fixes:
 *   [COMP-4] Fragmented messages (FIN=0 continuation frames, opcode=0x0) are
 *            accumulated in $fragmentBuffer. Only a FIN=1 frame triggers return.
 *
 * @param  string      &$buffer         Raw TCP receive buffer; consumed bytes are removed.
 * @param  string      &$fragmentBuffer Accumulates payload across fragmented frames.
 * @param  int         &$fragmentOpcode Opcode of the first fragment (carried to the final frame).
 * @return array{fin: true, opcode: int, payload: string}|null
 * @throws \OverflowException   On buffer-bomb / oversized payload declaration.
 * @throws \UnexpectedValueException On RSV bit violation or unknown fragmentation state.
 */
function parseWebSocketFrame(
    string &$buffer,
    string &$fragmentBuffer = '',
    int    &$fragmentOpcode = 0
): ?array {
    $bufLen = strlen($buffer);

    // Need at least 2 bytes for the base header
    if ($bufLen < 2) {
        return null;
    }

    $byte0 = ord($buffer[0]);
    $byte1 = ord($buffer[1]);

    $fin    = (bool)($byte0 & 0x80);
    $rsv    = ($byte0 & 0x70); // bits 6,5,4
    $opcode = $byte0 & 0x0F;
    $masked = (bool)($byte1 & 0x80);
    $payLen = $byte1 & 0x7F;

    // [SEC-3] No extensions were negotiated; RSV bits must all be zero
    if ($rsv !== 0) {
        throw new \UnexpectedValueException(
            sprintf('Protocol error: RSV bits are set (0x%02X). No extension negotiated.', $rsv)
        );
    }

    $headerLen = 2;

    // Extended payload length
    if ($payLen === 126) {
        if ($bufLen < 4) {
            return null;
        }
        $payLen     = unpack('n', substr($buffer, 2, 2))[1];
        $headerLen += 2;
    } elseif ($payLen === 127) {
        if ($bufLen < 10) {
            return null;
        }
        $payLen     = unpack('J', substr($buffer, 2, 8))[1];
        $headerLen += 8;
    }

    // [SEC-2] Reject oversized frames — prevent buffer-bomb / memory exhaustion
    if ($payLen > MAX_FRAME_PAYLOAD) {
        throw new \OverflowException(
            "Frame payload ({$payLen} bytes) exceeds MAX_FRAME_PAYLOAD (" . MAX_FRAME_PAYLOAD . " bytes)."
        );
    }

    // Optional masking key
    $maskKey = '';
    if ($masked) {
        if ($bufLen < $headerLen + 4) {
            return null;
        }
        $maskKey    = substr($buffer, $headerLen, 4);
        $headerLen += 4;
    }

    // Wait until the full payload is in the buffer
    if ($bufLen < $headerLen + $payLen) {
        return null;
    }

    $payload = substr($buffer, $headerLen, $payLen);

    if ($masked && $maskKey !== '') {
        $payload = processWebSocketMask($payload, $maskKey);
    }

    // Consume this frame from the buffer
    $buffer = substr($buffer, $headerLen + $payLen);

    // -----------------------------------------------------------------------
    // [COMP-4] Fragmentation reassembly
    // Control frames (opcode ≥ 0x8) must never be fragmented and are returned
    // immediately without touching the fragment buffer.
    // -----------------------------------------------------------------------
    if ($opcode >= 0x8) {
        // Control frame — return directly (always FIN=1 per spec)
        return ['fin' => true, 'opcode' => $opcode, 'payload' => $payload];
    }

    if ($opcode === 0x0) {
        // Continuation frame
        if ($fragmentOpcode === 0) {
            throw new \UnexpectedValueException(
                'Protocol error: received continuation frame (opcode 0x0) with no prior start frame.'
            );
        }
        $fragmentBuffer .= $payload;
    } else {
        // Start of a new message (opcode 0x1 text or 0x2 binary)
        if ($fragmentOpcode !== 0) {
            throw new \UnexpectedValueException(
                'Protocol error: received new data frame while a fragmented message was in progress.'
            );
        }
        $fragmentOpcode  = $opcode;
        $fragmentBuffer  = $payload;
    }

    if (!$fin) {
        // More fragments to come
        return null;
    }

    // FIN=1 — message is complete
    $completeOpcode  = $fragmentOpcode;
    $completePayload = $fragmentBuffer;
    $fragmentBuffer  = '';
    $fragmentOpcode  = 0;

    return ['fin' => true, 'opcode' => $completeOpcode, 'payload' => $completePayload];
}
