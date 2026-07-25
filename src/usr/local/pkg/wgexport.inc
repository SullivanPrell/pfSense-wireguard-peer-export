<?php
/*
 * wgexport.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2026 3um3le3ee <3um3le3ee@mail.com>
 * All rights reserved.
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
// wgexport.inc — WG Suite package include
//
// Loaded by pfSense for every page in this package via <include_file>.
// Contains:
//   - Package install / deinstall / upgrade hooks
//   - Shared config helpers used across all WGX pages
// =========================================================================

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");

define('WGX_VERSION',  '1.2.0');
define('WGX_PKG_NAME', 'pfSense-pkg-wg-export');
define('WGX_DIR',      '/usr/local/www/wgx');
define('WGX_DB_DIR',   '/var/db');

// =========================================================================
// Shared config helpers
// =========================================================================

/**
 * Read the WGX global settings from config, applying defaults for any
 * missing keys.  Safe to call before any settings have been saved.
 */
function wgx_get_settings(): array
{
    $s = config_get_path('installedpackages/wgexport/config/0', null);

    $defaults = [
        'sync_enable'      => 'false',
        'sync_ip'          => '',
        'sync_user'        => 'admin',
        'sync_pass'        => '',
        'strict_tls'       => 'false',
        'enforce_psk'      => 'false',
        'fallback_subnets' => '192.168.101.0/24',
        'default_dns'      => '8.8.8.8, 8.8.4.4',
        'default_ka'       => '25',
        'default_tier'     => 'admin',
        'key_rotation_days'=> '90',
        'enable_geo'       => 'false',
        'quota_limit_gb'   => '100',
        'auto_cron'        => 'true',
    ];

    if (!is_array($s)) {
        return $defaults;
    }

    foreach ($defaults as $k => $v) {
        if (!isset($s[$k])) {
            $s[$k] = $v;
        }
    }

    return $s;
}

/**
 * Persist WGX global settings.
 */
function wgx_save_settings(array $settings): void
{
    config_set_path('installedpackages/wgexport/config/0', $settings);
    write_config("WG Suite: Saved Global Settings");
}

/**
 * Return the peer list from config as a plain indexed array.
 * Handles both the legacy single-item and multi-item XML layouts.
 */
function wgx_get_peers(): array
{
    $peers = config_get_path('installedpackages/wireguard/peers/item', []);
    if (!is_array($peers)) {
        return [];
    }
    // Single peer stored as associative array, not wrapped in a list
    if (!empty($peers) && !isset($peers[0])) {
        return [$peers];
    }
    return $peers;
}

/**
 * Return the tunnel list from config as a plain indexed array.
 */
function wgx_get_tunnels(): array
{
    $tunnels = config_get_path('installedpackages/wireguard/tunnels/item', []);
    if (!is_array($tunnels)) {
        return [];
    }
    if (!empty($tunnels) && !isset($tunnels[0])) {
        return [$tunnels];
    }
    return $tunnels;
}

// =========================================================================
// Cron helpers
// =========================================================================

/**
 * Register or remove the WGX cron job for wgx_expire.php.
 */
function wgx_configure_cron(bool $enable): void
{
    install_cron_job(
        '/usr/local/bin/php -q /usr/local/www/wgx/wgx_expire.php',
        $enable,
        '*/5', '*', '*', '*', '*',
        'root'
    );
    if (function_exists('configure_cron')) {
        configure_cron();
    }
}

// =========================================================================
// Package install hook
// Called from wgexport.xml <custom_php_install_command>
// =========================================================================

function wgx_install(): void
{
    // Ensure web directory exists
    if (!is_dir(WGX_DIR)) {
        mkdir(WGX_DIR, 0755, true);
    }

    // Register cron job
    wgx_configure_cron(true);

    // Initialise default settings if not already present
    $settings = wgx_get_settings();
    if (config_get_path('installedpackages/wgexport/config/0', null) === null) {
        wgx_save_settings($settings);
    }

    syslog(LOG_NOTICE, "WG Suite " . WGX_VERSION . ": Package installed successfully.");
}

// =========================================================================
// Package deinstall hook
// Called from wgexport.xml <custom_php_deinstall_command>
// =========================================================================

function wgx_deinstall(): void
{
    // Remove cron job
    wgx_configure_cron(false);

    // Clean up runtime data files (not config — user may reinstall)
    $cleanup = [
        '/var/db/wgx_telemetry_archive.json',
        '/var/db/wgx_ip_reputation.json',
        '/var/db/wgx_gps_locations.json',
        '/var/db/wgx_tor_exits.txt',
        '/tmp/wgx_expire.lock',
        '/tmp/wgx_telemetry_cache.json',
    ];
    foreach ($cleanup as $f) {
        // unlink_if_exists() is CE-only; use a safe cross-version wrapper
        if (function_exists('unlink_if_exists')) {
            unlink_if_exists($f);
        } elseif (file_exists($f)) {
            @unlink($f);
        }
    }

    // Remove WGX_THROTTLED alias
    $aliases = config_get_path('aliases/alias', []);
    $aliases = array_values(array_filter($aliases, function($a) {
        return ($a['name'] ?? '') !== 'WGX_THROTTLED';
    }));
    config_set_path('aliases/alias', $aliases);

    // Remove WGX_THROTTLED floating block rule
    $rules = config_get_path('filter/rule', []);
    $rules = array_values(array_filter($rules, function($r) {
        return ($r['descr'] ?? '') !== 'WG Suite: Block over-quota peers [WGX_THROTTLED]';
    }));
    config_set_path('filter/rule', $rules);

    write_config('WG Suite: Removed WGX_THROTTLED alias and firewall rule.');
    if (function_exists('filter_configure')) {
        filter_configure();
    }

    syslog(LOG_NOTICE, "WG Suite: Package uninstalled and cleaned up.");
}
