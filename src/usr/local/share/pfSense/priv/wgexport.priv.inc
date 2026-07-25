<?php
/*
 * wgexport.priv.inc
 * WG Suite privilege definitions
 */

global $priv_list;

$priv_list['page-vpn-wgsuite'] = [];
$priv_list['page-vpn-wgsuite']['name']  = 'WebCfg - VPN: WG Suite';
$priv_list['page-vpn-wgsuite']['descr'] = 'Allow access to WG Suite pages.';
$priv_list['page-vpn-wgsuite']['match'] = [
    'wgx/vpn_wg_export.php*',
    'wgx/vpn_wg_dashboard.php*',
    'wgx/vpn_wg_setup.php*',
    'wgx/vpn_wg_audit.php*',
    'wgx/vpn_wg_credits.php*',
    'wgx/vpn_wg_map.php*',
    'wgx/vpn_wg_checkin.php*',
];
