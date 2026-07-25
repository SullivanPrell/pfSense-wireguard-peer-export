<?php
/*
 * vpn_wg_audit.php
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

$pgtitle = [gettext("VPN"), gettext("WG Suite"), gettext("Audit Logs")];
$pglinks = [null, "/wg/vpn_wg_tunnels.php", "@self"];
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Dashboard"), false, "/wgx/vpn_wg_dashboard.php");
$tab_array[] = array(gettext("Export"), false, "/wgx/vpn_wg_export.php");
$tab_array[] = array(gettext("Setup"), false, "/wgx/vpn_wg_setup.php");
$tab_array[] = array(gettext("Audit"), true, "/wgx/vpn_wg_audit.php");
display_top_tabs($tab_array);

$log_lines = [];

// Date range filter — default to today
$filter_from    = trim($_GET['from'] ?? date('Y-m-d'));
$filter_to      = trim($_GET['to']   ?? date('Y-m-d'));
$filter_from_ts = strtotime($filter_from . ' 00:00:00') ?: 0;
$filter_to_ts   = strtotime($filter_to   . ' 23:59:59') ?: PHP_INT_MAX;

// Primary source: dedicated WG Suite audit log written by wgx_audit_log()
// This is reliable across all pfSense versions unlike syslog routing.
// Secondary source: system syslog as fallback for legacy events.
$all_lines = [];

$wgx_log = '/var/db/wgx_audit.log';
foreach ([$wgx_log, $wgx_log . '.1'] as $lf) {
    if (file_exists($lf) && is_readable($lf)) {
        $raw = [];
        // Pre-filter by date range at grep level — avoids loading thousands of irrelevant lines
        // WGX log format starts with YYYY-MM-DD so we can grep the date range directly
        $dates_to_grep = [];
        $d = strtotime($filter_from);
        while ($d <= strtotime($filter_to)) {
            $dates_to_grep[] = date('Y-m-d', $d);
            $d = strtotime('+1 day', $d);
            if (count($dates_to_grep) > 31) break; // safety cap
        }
        $grep_pattern = implode('\|', $dates_to_grep);
        exec('grep -a ' . escapeshellarg($grep_pattern) . ' ' . escapeshellarg($lf) . ' 2>/dev/null | tail -n 3000', $raw);
        $all_lines = array_merge($all_lines, $raw);
    }
}

// Also pull from syslog sources for events logged before this version
foreach (['/var/log/system.log', '/var/log/nginx.log', '/var/log/php-fpm.log'] as $lf) {
    if (file_exists($lf) && is_readable($lf)) {
        $raw = [];
        exec('grep -a "WG Suite" ' . escapeshellarg($lf) . ' 2>/dev/null | tail -n 2000', $raw);
        $all_lines = array_merge($all_lines, $raw);
    }
}

// Parse and filter lines — handle both formats:
//   WGX audit format: "2026-06-04 14:32:11 [WG Suite] message"
//   Syslog format:    "Jun  4 14:32:11 hostname php: WG Suite: message"
$current_year = (int)date('Y');
$seen = []; // deduplicate

foreach (array_reverse($all_lines) as $line) {
    if (empty(trim($line))) continue;

    $time = '';
    $msg  = '';

    // WGX dedicated log format: YYYY-MM-DD HH:MM:SS [WG Suite] user - message
    if (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[WG Suite\] (.+)$/', $line, $m)) {
        $line_ts = strtotime($m[1]) ?: 0;
        if ($line_ts && ($line_ts < $filter_from_ts || $line_ts > $filter_to_ts)) continue;
        $time = $m[1];
        $msg  = $m[2];

        // Syslog format: Mon DD HH:MM:SS ... Configuration Change: user@ip... WG Suite: message
    } elseif (preg_match('/^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+.*?(?:Configuration Change:\s*([^@]+)@[^:]*:\s*)?WG Suite[:\s]+(.+)$/', $line, $m)) {
        $line_ts = strtotime($m[1] . ' ' . $current_year) ?: 0;
        if ($line_ts && ($line_ts < $filter_from_ts || $line_ts > $filter_to_ts)) continue;
        $time = $m[1];
        $user = !empty($m[2]) ? trim($m[2]) : 'System';
        $msg  = $user . ' - ' . trim($m[3]);

    } else {
        continue; // skip lines that don't match either format
    }

    $dedup_key = $time . '|' . $msg;
    if (isset($seen[$dedup_key])) continue;
    $seen[$dedup_key] = true;

    $log_lines[] = [
        'time' => htmlspecialchars($time),
        'msg'  => htmlspecialchars($msg),
    ];

    if (count($log_lines) >= 500) break;
}
?>

<style>
@media (max-width: 767px) {
    #auditTable thead { display: none; }
    #auditTable tr { display: block; border-bottom: 2px solid rgba(128,128,128,0.2); padding: 6px 0; }
    #auditTable td { display: block; text-align: left !important; padding: 3px 8px; border: none; white-space: normal !important; }
    .col-sm-3, .col-sm-4, .col-sm-6, .col-sm-8 { width: 100% !important; margin-bottom: 6px; }
    .panel-body { padding: 10px; }
    .input-group { margin-bottom: 6px; }
}
</style>
<div class="panel panel-default">
<div class="panel-heading"><h2 class="panel-title">System Audit Trail</h2></div>
<div class="panel-body">
<form method="get" action="" class="row form-group">
<div class="col-sm-3">
<div class="input-group">
<span class="input-group-addon"><i class="fa fa-calendar"></i></span>
<input type="date" name="from" class="form-control" value="<?= htmlspecialchars($filter_from) ?>" title="From date">
</div>
</div>
<div class="col-sm-3">
<div class="input-group">
<span class="input-group-addon"><i class="fa fa-calendar"></i></span>
<input type="date" name="to" class="form-control" value="<?= htmlspecialchars($filter_to) ?>" title="To date">
</div>
</div>
<div class="col-sm-6">
<button type="submit" class="btn btn-default"><i class="fa fa-filter"></i> Apply</button>
<a href="?" class="btn btn-default"><i class="fa fa-times"></i> Today</a>
<span class="text-muted small">Source: WG Suite audit log + system log</span>
</div>
</form>
<div class="row" style="margin-bottom:15px;">
<div class="col-sm-4">
<div class="input-group">
<span class="input-group-addon"><i class="fa fa-search"></i></span>
<input type="text" id="searchLogs" class="form-control" placeholder="Search events, IPs, or users...">
</div>
</div>
<div class="col-sm-8 text-right">
<span class="text-muted" style="margin-right: 15px;"><i class="fa fa-shield"></i> Immutable system log (Managed by pfSense)</span>
<button class="btn btn-default" onclick="downloadCsv()"><i class="fa fa-download"></i> Download CSV</button>
<button class="btn btn-primary" onclick="location.reload();"><i class="fa fa-refresh"></i> Refresh Logs</button>
</div>
</div>
<div class="table-responsive">
<table class="table table-striped table-hover" id="auditTable">
<thead>
<tr>
<th style="width:18%;">Timestamp</th>
<th style="width:12%;">User</th>
<th>Action / Security Event</th>
</tr>
</thead>
<tbody>
<?php if(empty($log_lines)): ?>
<tr><td colspan="3" class="text-center text-muted">No audit logs found. Provision a peer to see events.</td></tr>
<?php else: foreach($log_lines as $log): ?>
<?php
// Split "Username - action" into separate columns if the format is present
$log_user   = '';
$log_action = $log['msg'];
if (preg_match('/^([^-]+) - (.+)$/', $log['msg'], $lm)) {
    $log_user   = trim($lm[1]);
    $log_action = trim($lm[2]);
}
?>
<tr data-log="1">
<td class="text-nowrap text-muted" style="width:18%;"><i class="fa fa-clock-o"></i> <?= $log['time'] ?></td>
<td style="width:12%;">
<?php if ($log_user): ?>
<span class="label label-default"><i class="fa fa-user"></i> <?= htmlspecialchars($log_user) ?></span>
<?php endif; ?>
</td>
<td><strong><?= htmlspecialchars($log_action) ?></strong></td>
</tr>
<?php endforeach; endif; ?>
</tbody>
</table>
</div>
<div class="row" style="margin-top:10px;">
<div class="col-sm-6 text-muted" id="auditCount"></div>
<div class="col-sm-6 text-right">
<button class="btn btn-default btn-sm" id="auditLoadMore" style="display:none;">
<i class="fa fa-chevron-down"></i> Load More
</button>
</div>
</div>
</div>
</div>

<script>
const AUDIT_PAGE_SIZE = 25;
let auditVisible = AUDIT_PAGE_SIZE;

function auditRender(q) {
    const rows = Array.from(document.querySelectorAll('#auditTable tbody tr[data-log]'));
    let shown = 0;
    rows.forEach(tr => {
        const match = !q || tr.textContent.toLowerCase().includes(q);
        if (match && shown < auditVisible) { tr.style.display = ''; shown++; }
        else { tr.style.display = 'none'; }
    });
    const total = q ? rows.filter(tr => tr.textContent.toLowerCase().includes(q)).length : rows.length;
    document.getElementById('auditCount').textContent = 'Showing ' + Math.min(auditVisible, total) + ' of ' + total + ' events';
    document.getElementById('auditLoadMore').style.display = auditVisible < total ? '' : 'none';

    // Zero-results hint — suggest expanding date range if nothing found
    let hint = document.getElementById('auditZeroHint');
    if (!hint) {
        hint = document.createElement('div');
        hint.id = 'auditZeroHint';
        hint.className = 'alert alert-info';
        hint.style.marginTop = '10px';
        document.getElementById('auditCount').parentNode.appendChild(hint);
    }
    if (total === 0 && q) {
        hint.textContent = 'No results for "' + q + '" in the current date range. Try expanding the date filter above.';
        hint.style.display = '';
    } else {
        hint.style.display = 'none';
    }
}

function downloadCsv() {
    const rows = Array.from(document.querySelectorAll('#auditTable tbody tr[data-log]'))
    .filter(tr => tr.style.display !== 'none');
    const lines = ['Timestamp,User,Action'];
    rows.forEach(tr => {
        const cells = tr.querySelectorAll('td');
        const ts     = cells[0] ? cells[0].textContent.trim().replace(/\s+/g, ' ') : '';
    const user   = cells[1] ? cells[1].textContent.trim() : '';
    const action = cells[2] ? cells[2].textContent.trim() : '';
    lines.push([ts, user, action].map(v => '"' + v.replace(/"/g, '""') + '"').join(','));
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = 'wgx_audit_<?= htmlspecialchars($filter_from) ?>_to_<?= htmlspecialchars($filter_to) ?>.csv';
    a.click();
    URL.revokeObjectURL(a.href);
}

document.getElementById('searchLogs').addEventListener('input', function () {
    auditVisible = AUDIT_PAGE_SIZE;
    auditRender(this.value.toLowerCase());
});

document.getElementById('auditLoadMore').addEventListener('click', function () {
    auditVisible += AUDIT_PAGE_SIZE;
    auditRender(document.getElementById('searchLogs').value.toLowerCase());
});

auditRender('');
</script>
<?php include("foot.inc"); ?>
