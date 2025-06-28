#!/usr/bin/env bash

# ───────────────────────────────────────────────────────────
# ICS Passive Monitoring Pipeline (Parallel + Cleanup)
# Description:
#   - Captures Modbus traffic every 30s
#   - Analyzes previous PCAP while next capture is running
#   - Cleans up old files to save disk
# Author: Elyud Hybrid Version (Fixed for Race Conditions)
# ───────────────────────────────────────────────────────────

# CONFIG
INTERFACE="eth0"
CAPTURE_DURATION=30
BASE_DIR="./captured_data"
PCAP_DIR="$BASE_DIR/pcaps"
LOGS_BASE_DIR="$BASE_DIR/logs"
ALERTS_DIR="$BASE_DIR/output"
ZEEK_BIN="/opt/zeek/bin/zeek"
PLUGIN_DIR="/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"
DETECT_SCRIPT="analyser_engine/detect.py"
POLICY_FILE="analyser_engine/policy_rules/plc1_policy.yaml"
PYTHON="python3"
RETENTION_DAYS=2

mkdir -p "$PCAP_DIR" "$LOGS_BASE_DIR" "$ALERTS_DIR"

echo "[+] ICS Passive Detection Loop Started — Capturing every $CAPTURE_DURATION seconds..."

LAST_PCAP=""

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="$PCAP_DIR/segment_${TIMESTAMP}.pcap"
    LOG_DIR="$LOGS_BASE_DIR/segment_${TIMESTAMP}"
    ALERT_FILE="$ALERTS_DIR/alerts_${TIMESTAMP}.json"

    echo "[INFO] Starting capture for $CAPTURE_DURATION seconds → $PCAP_FILE"
    timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -w "$PCAP_FILE" 'port 502' &
    CAPTURE_PID=$!

    sleep "$CAPTURE_DURATION"
    wait "$CAPTURE_PID"

    if [[ ! -s "$PCAP_FILE" ]]; then
        echo "[WARN] PCAP $PCAP_FILE was not created or is empty. Skipping this cycle."
        rm -f "$PCAP_FILE"
        LAST_PCAP=""
        continue
    else
        echo "[OK] Captured $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1))"
    fi

    if [[ -n "$LAST_PCAP" && -f "$LAST_PCAP" ]]; then
        LAST_TS=$(basename "$LAST_PCAP" | cut -d'_' -f2 | cut -d'.' -f1)
        LAST_LOG_DIR="$LOGS_BASE_DIR/segment_${LAST_TS}"
        LAST_ALERT_FILE="$ALERTS_DIR/alerts_${LAST_TS}.json"

        mkdir -p "$LAST_LOG_DIR"
        echo "test: confirming write access" > "$LAST_LOG_DIR/test.txt"

        ABS_PCAP=$(readlink -f "$LAST_PCAP")
        cd "$LAST_LOG_DIR"
        ZEEK_LOG_DIR="$LAST_LOG_DIR" "$ZEEK_BIN" -Cr "$ABS_PCAP" "$PLUGIN_DIR"

        if [[ $? -eq 0 && -s "$LAST_LOG_DIR/modbus.log" ]]; then
            echo "[DEBUG] Running analyzer on $LAST_LOG_DIR/modbus.log"
            "$PYTHON" "$DETECT_SCRIPT" --logdir "$LAST_LOG_DIR" --policy "$POLICY_FILE" --out "$LAST_ALERT_FILE"
        else
            echo "[DEBUG] Zeek did not generate logs in $LAST_LOG_DIR"
        fi
    fi

    LAST_PCAP="$PCAP_FILE"

    find "$PCAP_DIR" -type f -name "*.pcap" -mtime +$RETENTION_DAYS -delete
    find "$LOGS_BASE_DIR" -type d -name "segment_*" -mtime +$RETENTION_DAYS -exec rm -rf {} +
    find "$ALERTS_DIR" -type f -name "alerts_*.json" -mtime +$RETENTION_DAYS -delete

done

