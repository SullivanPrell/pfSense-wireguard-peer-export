#!/bin/sh
# pfSense Basic Security & Integrity Audit
# This script is read-only and will not modify your system.

echo "=========================================================="
echo " Starting pfSense Integrity Audit..."
echo "=========================================================="
echo ""

# 1. CORE SYSTEM INTEGRITY CHECK
echo ">>> 1. Checking core system files against Netgate signatures..."
echo "    (This compares hashes of installed files. It may take a minute or two.)"
# -s checks checksums, -q keeps it quiet unless there is a mismatch
pkg check -sq
if [ $? -eq 0 ]; then
    echo "    [OK] No core package checksum mismatches found."
else
    echo "    [WARNING] Some package files have been modified! Review the output above."
fi
echo ""

# 2. RECENTLY MODIFIED FILES IN CRITICAL DIRECTORIES
echo ">>> 2. Finding files modified in the last 7 days..."
echo "    (Looking in /etc, /usr/local/www, and /usr/local/etc)"
find /etc /usr/local/www /usr/local/etc -type f -mtime -7 | grep -v "/var/run" | grep -v "/var/db"
echo ""

# 3. HIDDEN FILES IN THE WEB DIRECTORY
echo ">>> 3. Checking for suspicious hidden files in the WebGUI directory..."
echo "    (Web files should rarely be hidden)"
find /usr/local/www -name ".*" -type f
echo ""

# 4. UNRECOGNIZED STARTUP SCRIPTS
echo ">>> 4. Listing custom startup scripts (/usr/local/etc/rc.d/)..."
echo "    (Review these to ensure you recognize them)"
ls -la /usr/local/etc/rc.d/ | grep -v "total"
echo ""

# 5. CHECK FOR ROGUE ADMIN ACCOUNTS
echo ">>> 5. Listing users with root/admin shell access..."
echo "    (Only accounts you created and 'root' should be here)"
grep -E 'sh$|csh$|bash$|tcsh$' /etc/passwd
echo ""

# 6. WG SUITE BOOT-PERSISTENCE BACKDOOR (upstream 1.0.8 / 1.0.9)
echo ">>> 6. Checking for the WG Suite boot-persistence auto-installer..."
echo "    (Installed by upstream pfSense-pkg-wg-export 1.0.8 and 1.0.9)"
wgx_hits=0
for cfg in /conf/config.xml /cf/conf/config.xml; do
    [ -f "$cfg" ] || continue
    if grep -q 'raw\.githubusercontent\.com/3um3le3ee' "$cfg" 2>/dev/null; then
        wgx_hits=$((wgx_hits + 1))
        echo "    [CRITICAL] Found in ${cfg}:"
        grep -n 'raw\.githubusercontent\.com/3um3le3ee' "$cfg" | sed 's/^/      /'
    fi
done

if [ "$wgx_hits" -eq 0 ]; then
    echo "    [OK] No WG Suite boot-persistence entry found."
else
    echo ""
    echo "    This runs at every boot as root. It fetches version.json from a"
    echo "    third-party GitHub repository and installs whatever package the"
    echo "    'url' field names, using 'pkg add -fM'. It survives pfSense"
    echo "    upgrades, because those replace /usr/local/www but keep config.xml."
    echo ""
    echo "    REMOVE IT VIA THE WEBGUI: System > Advanced > Shellcmd — delete the"
    echo "    entry, then reboot and re-run this audit to confirm it is gone."
    echo "    Do not hand-edit config.xml; a malformed file will not parse."
fi
echo ""

# 7. ANY BOOT COMMAND THAT PULLS FROM THE NETWORK
echo ">>> 7. Checking for boot commands that download or install from the network..."
echo "    (Catches the same pattern under a different URL)"
found_net=0
for cfg in /conf/config.xml /cf/conf/config.xml; do
    [ -f "$cfg" ] || continue
    hits=$(grep -o '<shellcmd>[^<]*</shellcmd>' "$cfg" 2>/dev/null \
        | grep -E 'pkg (add|install)|fetch |curl |wget ')
    if [ -n "$hits" ]; then
        found_net=1
        echo "$hits" | sed 's/^/      [REVIEW] /'
    fi
done
if [ "$found_net" -eq 0 ]; then
    echo "    [OK] No boot shellcmd fetches or installs from the network."
else
    echo "    Review each of these. A boot command that installs a package from"
    echo "    a URL hands root on this firewall to whoever controls that URL."
fi
echo ""

echo "=========================================================="
echo " Audit Complete."
echo " Note: Your custom 'vpn_wg_export.php' and widget will"
echo " likely show up in the 'Recently Modified' list!"
echo "=========================================================="