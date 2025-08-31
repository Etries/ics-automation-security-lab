#!/usr/bin/env bash

# ─── Configuration ────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Paths relative to the script's location
CONFIG_DIR="$SCRIPT_DIR/../config"
TOOLS_DIR="$SCRIPT_DIR" 
DETECT_SCRIPT="$TOOLS_DIR/detect.py"
INCIDENT_SCRIPT="$TOOLS_DIR/incident_builder.py"
POLICY_FILE="$CONFIG_DIR/policies.yaml"
ADDR_MAP="$CONFIG_DIR/addr_map.yaml"
CONF_FILE="$CONFIG_DIR/supervisor.conf"

# Load user config if it exists
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"


ZEEK_BIN=${ZEEK_BIN:-"/opt/zeek/bin/zeek"}
PYTHON_BIN=${PYTHON_BIN:-"python3"}
INTERFACE=${INTERFACE:-"eth0"}
CAPTURE_DURATION=${CAPTURE_DURATION:-30}
PCAP_SNAPLEN=${PCAP_SNAPLEN:-65535}
PLUGIN_DIR=${PLUGIN_DIR:-"/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"} 
RETENTION_MINUTES=${RETENTION_MINUTES:-60}
BASE_DIR="$SCRIPT_DIR/../runtime"

# ─── Runtime Paths ────────────────────────────────────────────

PCAP_DIR="$BASE_DIR/pcaps"
ZEEK_LOG_DIR="$BASE_DIR/zeek_logs"
VLAN_LOG_DIR="$BASE_DIR/vlan_logs"
ALERT_DIR="$BASE_DIR/alerts"
INCIDENT_DIR="$BASE_DIR/incidents"


mkdir -p "$PCAP_DIR" "$ZEEK_LOG_DIR" "$VLAN_LOG_DIR" "$ALERT_DIR" "$INCIDENT_DIR"

# ─── Cleanup on Exit ──────────────────────────────────────────

trap "echo 'Shutting down...'; kill 0; exit 0" SIGINT SIGTERM

LAST_PCAP=""

echo "[INFO] Supervisor started. Monitoring interface '$INTERFACE' for Modbus traffic on port 502."
echo "[INFO] Press Ctrl+C to stop."


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

            #Zeek Deep Modbus Parsing
            echo "  [-] Running Zeek analysis..."
            (cd "$LAST_SEGMENT_DIR" && "$ZEEK_BIN" -Cr "$LAST_PCAP" "$PLUGIN_DIR" >/dev/null 2>&1)

            if [[ -f "$LAST_SEGMENT_DIR/modbus_detailed.log" ]]; then
                # Generate UID-to-VLAN Map
                echo "  [-] Creating VLAN map for each transaction..."
                
                tshark -r "$LAST_PCAP" -Y "modbus" -T fields -e zeek.uid -e vlan.id | sort -u | awk 'NF==2' > "$VLAN_MAP_FILE"

                # Detection Engine
                echo "  [-] Running context-aware detection..."
                "$PYTHON_BIN" "$DETECT_SCRIPT" \
                    --log "$LAST_SEGMENT_DIR/modbus_detailed.log" \
                    --policy "$POLICY_FILE" \
                    --addrmap "$ADDR_MAP" \
                    --vlan-map "$VLAN_MAP_FILE" \
                    --out "$LAST_ALERT_FILE"

                # Incident Report if alerts were generated
                if [[ -s "$LAST_ALERT_FILE" ]]; then
                    echo "  [-] Alerts found. Generating incident report..."
                   
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


    wait "$CAPTURE_PID"

    if [[ ! -s "$PCAP_FILE" ]]; then
        echo "[!] [$TS] Capture file is empty. Discarding."
        rm -f "$PCAP_FILE"
        LAST_PCAP=""
    else
        echo "[OK] [$TS] Finished capture: $PCAP_FILE ($(du -h "$PCAP_FILE" | cut -f1))"
        LAST_PCAP="$PCAP_FILE"
    fi

    # Housekeeping to remove old files
    if [[ -n "$RETENTION_MINUTES" ]]; then
        find "$PCAP_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
        find "$ZEEK_LOG_DIR" -type d -mmin +$RETENTION_MINUTES -exec rm -rf {} + 2>/dev/null
        find "$ALERT_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
        find "$INCIDENT_DIR" -type f -mmin +$RETENTION_MINUTES -delete 2>/dev/null
    fi
done 
