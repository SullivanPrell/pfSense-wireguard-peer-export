<?php
/*
 * Minimal pfSense environment stub — enough to render WGX pages off-box.
 *
 * Every function here is a stand-in for one pfSense supplies at runtime.
 * Nothing touches the real system: no config is written, no command runs.
 * The point is to execute the pages' top-level and render paths so the
 * emitted HTML can be checked for structural damage.
 */

// ---------------------------------------------------------------- config --
$GLOBALS['__cfg'] = [];
$GLOBALS['config'] = &$GLOBALS['__cfg'];
$g = ['word' => 'pfSense', 'product_label' => 'pfSense'];

function __path_get(array $a, string $path, $default = null) {
    $cur = $a;
    foreach (explode('/', trim($path, '/')) as $seg) {
        if ($seg === '') { continue; }
        if (is_array($cur) && array_key_exists($seg, $cur)) { $cur = $cur[$seg]; }
        else { return $default; }
    }
    return $cur;
}
function __path_set(array &$a, string $path, $val) {
    $cur = &$a;
    foreach (explode('/', trim($path, '/')) as $seg) {
        if ($seg === '') { continue; }
        if (!isset($cur[$seg]) || !is_array($cur[$seg])) { $cur[$seg] = []; }
        $cur = &$cur[$seg];
    }
    $cur = $val;
}

function config_get_path(string $path, $default = null) {
    return __path_get($GLOBALS['__cfg'], $path, $default);
}
function config_set_path(string $path, $val) {
    __path_set($GLOBALS['__cfg'], $path, $val);
    return $val;
}
function config_del_path(string $path) {
    $parts = explode('/', trim($path, '/'));
    $leaf = array_pop($parts);
    $cur = &$GLOBALS['__cfg'];
    foreach ($parts as $seg) {
        if (!isset($cur[$seg])) { return; }
        $cur = &$cur[$seg];
    }
    unset($cur[$leaf]);
}
function write_config($msg = '') { $GLOBALS['__writes'][] = $msg; return true; }
function make_config_revision_entry($a = null, $b = null) { return []; }

// ------------------------------------------------------------------ gui --
function csrf_check($die = true) { return true; }
function display_top_tabs($tabs, $no_drop = false, $type = 'tabs', $cls = '') {
    echo "<ul class=\"nav nav-tabs\">";
    foreach ((array)$tabs as $t) {
        $name = htmlspecialchars((string)($t[0] ?? ''));
        $href = htmlspecialchars((string)($t[2] ?? '#'));
        echo "<li><a href=\"{$href}\">{$name}</a></li>";
    }
    echo "</ul>";
}
function print_info_box($msg, $class = 'success', $btn = null, $btntext = '') {
    echo "<div class=\"alert alert-{$class}\">" . $msg . "</div>";
}

// ------------------------------------------------------------ subsystem --
function mark_subsystem_dirty($s) { return true; }
function clear_subsystem_dirty($s) { return true; }

// ------------------------------------------------------------ net utils --
function is_ipaddrv4($v) { return (bool)filter_var((string)$v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4); }
function is_ipaddrv6($v) { return (bool)filter_var((string)$v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6); }
function is_ipaddr($v)   { return is_ipaddrv4($v) || is_ipaddrv6($v); }
function is_subnet($v) {
    if (!is_string($v) || strpos($v, '/') === false) { return false; }
    [$ip, $bits] = explode('/', $v, 2);
    return is_ipaddr($ip) && ctype_digit($bits) && (int)$bits <= (is_ipaddrv6($ip) ? 128 : 32);
}
function gen_subnet($ip, $bits) {
    if (!is_ipaddrv4($ip)) { return ''; }
    $l = ip2long($ip); $m = $bits == 0 ? 0 : (~0 << (32 - (int)$bits)) & 0xFFFFFFFF;
    return long2ip($l & $m);
}
function gen_subnetv6($ip, $bits) { return is_ipaddrv6($ip) ? $ip : ''; }
function ip_in_subnet($ip, $subnet) {
    if (!is_subnet($subnet) || !is_ipaddrv4($ip)) { return false; }
    [$net, $bits] = explode('/', $subnet, 2);
    return gen_subnet($ip, $bits) === gen_subnet($net, $bits);
}
function get_interface_ip($if = 'wan') { return '203.0.113.10'; }
function get_configured_interface_with_descr($only = false) {
    return ['wan' => 'WAN', 'lan' => 'LAN', 'opt1' => 'WGWAN'];
}
function pfSense_get_ifaddrs($if = null) { return []; }

// ------------------------------------------------------------- exec/sys --
function mwexec($cmd, $mute = false, $clear = false) { $GLOBALS['__exec'][] = $cmd; return 0; }
function unlink_if_exists($f) { return file_exists($f) ? @unlink($f) : false; }
function install_cron_job($cmd, $en = true, $m = null, $h = null, $md = null, $mo = null, $wd = null, $who = 'root') {
    $GLOBALS['__cron'][] = [$cmd, $en];
    return true;
}
function configure_cron() { return true; }
function fastcgi_finish_request() { return true; }
function send_smtp_message($body, $subject, $force = false) { $GLOBALS['__mail'][] = $subject; return true; }

// ---------------------------------------------------- interfaces/filter --
function filter_configure() { return true; }
function filter_configure_sync($rdr = true) { return true; }
function interface_configure($if, $reload = false) { return true; }
function interfaces_configure() { return true; }
function interface_bring_down($if, $des = false, $ifcfg = false) { return true; }

// ------------------------------------------------------------ packages --
function sync_package($pkg) { return true; }

// ----------------------------------------------------------- wireguard --
function wg_resync() { return [true, 'stub']; }
function wg_toggle_wireguard($en = true) { return [true, 'stub']; }
function wg_tunnel_sync($tuns = null, $a = false, $b = false, $c = false) { return ['tunnels' => []]; }
function wg_delete_tunnel($name) { return [true, 'stub']; }
function setup_wg($a = null) { return true; }

// --------------------------------------------------------- page chrome --
// Deliberately balanced: any imbalance in captured output is the page's.
function __wgx_head() {
    echo "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>stub</title></head><body>\n<div id=\"content\">\n";
}
function __wgx_foot() {
    echo "\n</div>\n</body></html>\n";
}
