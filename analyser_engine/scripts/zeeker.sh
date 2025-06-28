#!/usr/bin/env bash

# ─────────────────────────────────────────────
# Debug Version: Zeek + ICSNPP Modbus Analyzer
# Shows all stdout and stderr from Zeek
# ─────────────────────────────────────────────

ZEEK_BIN="/opt/zeek/bin/zeek"
PLUGIN_DIR="/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"
PCAP_DIR="./captured_data/pcaps"
LOGS_BASE_DIR="./captured_data/logs"

mkdir -p "$LOGS_BASE_DIR"

for pcap in "$PCAP_DIR"/*.pcap; do
    [[ -f "$pcap" ]] || continue

    ts=$(basename "$pcap" | cut -d'_' -f2 | cut -d'.' -f1)
    log_dir="$LOGS_BASE_DIR/segment_$ts"
    mkdir -p "$log_dir"

    echo -e "\n[*] Processing $pcap → $log_dir"

    abs_pcap=$(readlink -f "$pcap")

    cd "$log_dir" || {
        echo "[ERR] Failed to cd into $log_dir"
        continue
    }

    echo "[DEBUG] Running Zeek: $ZEEK_BIN -Cr \"$abs_pcap\" \"$PLUGIN_DIR\""
    ZEEK_LOG_DIR="$log_dir" "$ZEEK_BIN" -Cr "$abs_pcap" "$PLUGIN_DIR"

    # Print summary
    if [[ -s "$log_dir/modbus.log" ]]; then
        echo "[+] ✅ Zeek analysis complete: modbus.log created."
    else
        echo "[!] ❌ Zeek ran but no modbus.log was created."
        echo "[INFO] Check for error output above or manually run:"
        echo "       cd \"$log_dir\" && ZEEK_LOG_DIR=. $ZEEK_BIN -Cr \"$abs_pcap\" \"$PLUGIN_DIR\""
    fi
done

