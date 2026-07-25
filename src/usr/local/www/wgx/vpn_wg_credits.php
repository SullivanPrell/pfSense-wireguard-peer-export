<?php
/*
 * vpn_wg_credits.php
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

$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("Credits")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
$extrahead = '<link rel="stylesheet" type="text/css" href="/wgx/wgx_credits.css">';
include("head.inc");

// Inject the tabs so the user doesn't feel lost
$tab_array = array();
$tab_array[] = array(gettext("Dashboard"), false, "/wgx/vpn_wg_dashboard.php");
$tab_array[] = array(gettext("Export"), false, "/wgx/vpn_wg_export.php");
$tab_array[] = array(gettext("Setup"), false, "/wgx/vpn_wg_setup.php");
$tab_array[] = array(gettext("Audit"), false, "/wgx/vpn_wg_audit.php");
$tab_array[] = array(gettext("Map"),     false, "/wgx/vpn_wg_map.php");
$tab_array[] = array(gettext("Credits"), true,  "/wgx/vpn_wg_credits.php");
display_top_tabs($tab_array);
?>

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><i class="fa fa-trophy icon-gold"></i> Hall of Fame & Acknowledgements</h2></div>
    <div class="panel-body">
        <div class="alert alert-info">
            <strong>Thank You!</strong> This tool exists because of the feedback, testing, and support from an amazing community.
        </div>

        <div class="row">
            <div class="col-sm-12">
            <div class="credit-card credit-card-success text-center">
            <h4 class="credit-title"><i class="fa fa-bug"></i> Testers</h4>
                    <p>For breaking things so we could fix them:</p>
                    <ul style="list-style-position: inside; padding-left: 0; text-align: left; display: inline-block;">
                        <li><strong>psp</strong> - Extensive Testing, Communication/Feedback. &#127942;</li>
                        <li><strong>LordR7</strong> - Github Contribution & Feedback.</li>
                        <li><strong>EnTaroYan</strong> - Github Contribution & Feedback.</li>
                        <li><strong>ionoci</strong> - Github Contribution & Feedback.</li>
                        <li><strong>Rex-odus</strong> - Github Contribution & Feedback.</li>
                        <li><strong>pfSense_fireball</strong> - Testing & Exposure.</li>
                        <li><strong>netblues</strong> - Testing & Feature Suggestion.</li>
                        <li><strong>keyser</strong> - Support & Encouragement.</li>
                        <li><strong>Jarhead</strong> - Feedback.</li>
                        <li><strong>patient0</strong> - Asking a question.</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-sm-12">
            <div class="credit-card credit-card-danger text-center">
            <h4 class="credit-title"><i class="fa fa-heart text-danger"></i> Project Support</h4>
                    <p>And a special thanks to everyone who downloaded, starred, or shared the project. You rock.</p>
                </div>
            </div>
        </div>
    </div>
    <div class="panel-footer text-right">
        <a href="/wgx/vpn_wg_export.php" class="btn btn-sm btn-primary"><i class="fa fa-arrow-left"></i> Back to Export Tool</a>
    </div>
</div>

<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title"><i class="fa fa-list-alt"></i> What's New</h2></div>
<div class="panel-body" style="padding:0;">
<table class="table table-striped" style="margin-bottom:0;">
<thead>
<tr>
<th style="width:12%;">Version</th>
<th style="width:15%;">Date</th>
<th>Changes</th>
</tr>
</thead>
<tbody>
<tr>
<td><span class="label label-success">v1.2.0</span></td>
<td>Jun 2026</td>
<td>
Mobile responsive layout across all pages &mdash;
<code>wg show all dump</code> consolidation (3&times; fewer subprocesses) &mdash;
WS server IPv6 fix, write timeout, periodic stats logging &mdash;
Tunnel client auto-reconnect with exponential backoff &mdash;
GPS check-in rate limiting and file locking &mdash;
Configurable business hours &mdash;
Expiry warning emails 24h before peer expiry &mdash;
DEV nuke gated behind <code>WGX_DEV_MODE</code> constant &mdash;
WS deployment service probe &mdash;
Audit log CSV export &mdash;
Credits tab across all pages
</td>
</tr>
<tr>
<td><span class="label label-info">v1.1.0</span></td>
<td>May 2026</td>
<td>
NOC dashboard with stat cards, sparklines, anomaly badges &mdash;
GPS check-in PWA &mdash;
S2S deployment wizard (Primary/Secondary role picker) &mdash;
HA Sync modal &mdash;
System audit trail at <code>/var/db/wgx_audit.log</code> &mdash;
WebSocket transport layer &mdash;
IP reputation and geolocation (opt-in) &mdash;
Bandwidth quota enforcement via pfSense alias
</td>
</tr>
<tr>
<td><span class="label label-default">v1.0.0</span></td>
<td>Apr 2026</td>
<td>
Initial release &mdash;
Peer provisioning wizard &mdash;
QR code export &mdash;
Bulk CSV import &mdash;
Peer expiry and scheduling &mdash;
Key rotation &mdash;
Dashboard widget &mdash;
pfSense CE + Plus (FreeBSD 15/16) support
</td>
</tr>
</tbody>
</table>
</div>
</div>

<?php include("foot.inc"); ?>
