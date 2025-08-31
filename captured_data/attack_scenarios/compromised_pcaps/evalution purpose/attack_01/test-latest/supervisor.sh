#!/usr/bin/env bash

# ─── Configuration ────────────────────────────────────────────

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define paths relative to the script's location
# This makes the script portable and independent of where it's called from.
CONFIG_DIR="$SCRIPT_DIR/../config"
TOOLS_DIR="$SCRIPT_DIR" # Assuming supervisor.sh is in the 'tools' directory
DETECT_SCRIPT="$TOOLS_DIR/detect.py"
INCIDENT_SCRIPT="$TOOLS_DIR/incident_builder.py"
POLICY_FILE="$CONFIG_DIR/policies.yaml" # Corrected filename
ADDR_MAP="$CONFIG_DIR/addr_map.yaml"
CONF_FILE="$CONFIG_DIR/supervisor.conf"

# Load user config if it exists
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

# Set defaults (can be overridden in supervisor.conf)
ZEEK_BIN=${ZEEK_BIN:-"/opt/zeek/bin/zeek"}
PYTHON_BIN=${PYTHON_BIN:-"python3"}
INTERFACE=${INTERFACE:-"eth0"}
CAPTURE_DURATION=${CAPTURE_DURATION:-30} # seconds
PCAP_SNAPLEN=${PCAP_SNAPLEN:-65535}
PLUGIN_DIR=${PLUGIN_DIR:-"/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"} # Example path, adjust if needed
RETENTION_MINUTES=${RETENTION_MINUTES:-60}
BASE_DIR="$SCRIPT_DIR/../runtime"

# ─── Runtime Paths ────────────────────────────────────────────

PCAP_DIR="$BASE_DIR/pcaps"
ZEEK_LOG_DIR="$BASE_DIR/zeek_logs"
VLAN_LOG_DIR="$BASE_DIR/vlan_logs"
ALERT_DIR="$BASE_DIR/alerts"
INCIDENT_DIR="$BASE_DIR/incidents"

# Create directories if they don't exist
mkdir -p "$PCAP_DIR" "$ZEEK_LOG_DIR" "$VLAN_LOG_DIR" "$ALERT_DIR" "$INCIDENT_DIR"

# ─── Cleanup on Exit ──────────────────────────────────────────

trap "echo 'Shutting down...'; kill 0; exit 0" SIGINT SIGTERM

LAST_PCAP=""

echo "[INFO] Supervisor started. Monitoring interface '$INTERFACE' for Modbus traffic on port 502."
echo "[INFO] Press Ctrl+C to stop."

# ─── Main Loop ────────────────────────────────────────────────

while true; do
    TS=$(date +%Y%m%d_%H%M%S)
    PCAP_FILE="$PCAP_DIR/segment_${TS}.pcap"

    echo
    echo "======================================================================"
    echo "[+] [$TS] Starting new capture for $CAPTURE_DURATION seconds -> $PCAP_FILE"
    echo "======================================================================"
    
    # Start capturing traffic in the background
    timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -s "$PCAP_SNAPLEN" -w "$PCAP_FILE" 'vlan and port 502' &
    CAPTURE_PID=$!

    # While the new capture is running, process the PREVIOUS capture
    if [[ -n "$LAST_PCAP" && -f "$LAST_PCAP" ]]; then
        # Run the analysis in a subshell to not block the main loop
        (
            LAST_TS=$(basename "$LAST_PCAP" .pcap | cut -d'_' -f2-)
            LAST_SEGMENT_DIR="$ZEEK_LOG_DIR/segment_$LAST_TS"
            LAST_ALERT_FILE="$ALERT_DIR/alerts_$LAST_TS.json"
            VLAN_MAP_FILE="$VLAN_LOG_DIR/vlan_map_$LAST_TS.log"
            INCIDENT_FILE="$INCIDENT_DIR/incident_report_$LAST_TS.json"
            
            mkdir -p "$LAST_SEGMENT_DIR"

            echo "[+] [$LAST_TS] Analyzing previous capture: $LAST_PCAP"

            # 1. Zeek Deep Modbus Parsing
            echo "  [-] Running Zeek analysis..."
            (cd "$LAST_SEGMENT_DIR" && "$ZEEK_BIN" -Cr "$LAST_PCAP" "$PLUGIN_DIR" >/dev/null 2>&1)

            if [[ -f "$LAST_SEGMENT_DIR/modbus_detailed.log" ]]; then
                # 2. Generate UID-to-VLAN Map
                echo "  [-] Creating VLAN map for each transaction..."
                # Corrected tshark command to handle multiple fields correctly
                tshark -r "$LAST_PCAP" -Y "tcp.port == 502" \
                 -T fields -e ip.src -e ip.dst -e vlan.id -E separator=$'\t' \
                 | awk 'NF==3 && $3 ~ /^[0-9]+$/ {print $1 "\t" $2 "\t" $3}' \
                 | sort -u > "$VLAN_MAP_FILE"


                # 3. Run Detection Engine
                echo "  [-] Running context-aware detection..."
                "$PYTHON_BIN" "$DETECT_SCRIPT" \
                    --log "$LAST_SEGMENT_DIR/modbus_detailed.log" \
                    --policy "$POLICY_FILE" \
                    --addrmap "$ADDR_MAP" \
                    --vlan-map "$VLAN_MAP_FILE" \
                    --out "$LAST_ALERT_FILE"

                # 4. Build Incident Report if alerts were generated
                if [[ -s "$LAST_ALERT_FILE" ]]; then
                    echo "  [-] Alerts found. Generating incident report..."
                    # *** THE FIX IS HERE ***
                    # Added the required --policy and --addrmap arguments to the incident builder call.
                    "$PYTHON_BIN" "$INCIDENT_SCRIPT" \
                        --alerts "$LAST_ALERT_FILE" \
                        --policy "$POLICY_FILE" \
                        --addrmap "$ADDR_MAP" \
                        --out "$INCIDENT_FILE" \
                        --format both
                else
                    echo "  [OK] No alerts found in this segment."
                fi
            else
                echo "[!] [$LAST_TS] No modbus_detailed.log found for $LAST_PCAP"
            fi
            echo "[OK] [$LAST_TS] Analysis complete for $LAST_PCAP"
        ) &
    fi

    # Wait for the current capture to finish
    wait "$CAPTURE_PID"

    if [[ ! -s "$PCAP_FILE" ]]; then
        echo "[!] [$TS] Capture file is empty. Discarding."
        rm -f "$PCAP_FILE"
        LAST_PCAP=""
    else
        echo "[OK] [$TS] Finished capture: $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1))"
        LAST_PCAP="$PCAP_FILE"
    fi

    # Optional: Housekeeping to remove old files
    if [[ -n "$RETENTION_MINUTES" ]]; then
        find "$PCAP_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
        find "$ZEEK_LOG_DIR" -type d -mmin +$RETENTION_MINUTES -exec rm -rf {} + 2>/dev/null
        find "$ALERT_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
        find "$INCIDENT_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
    fi
done 
