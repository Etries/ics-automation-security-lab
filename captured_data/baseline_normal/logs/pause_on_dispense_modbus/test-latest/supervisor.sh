#!/usr/bin/env bash

# ─── Configuration ────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../config"
DETECT_SCRIPT="$SCRIPT_DIR/../test-latest/detect.py"
INCIDENT_SCRIPT="$SCRIPT_DIR/../test-latest/incident_builder.py"
POLICY_FILE="$CONFIG_DIR/plc1_policy.yaml"
ADDR_MAP="$CONFIG_DIR/addr_map.yaml"
CONF_FILE="$CONFIG_DIR/supervisor.conf"

# Load user config
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

# Defaults (can be overridden in supervisor.conf)
ZEEK_BIN=${ZEEK_BIN:-"/opt/zeek/bin/zeek"}
PYTHON_BIN=${PYTHON_BIN:-"python3"}
INTERFACE=${INTERFACE:-"eth0"}
CAPTURE_DURATION=${CAPTURE_DURATION:-30}
PCAP_SNAPLEN=${PCAP_SNAPLEN:-65535}
PLUGIN_DIR=${PLUGIN_DIR:-"/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"}
RETENTION_MINUTES=${RETENTION_MINUTES:-60}
BASE_DIR=${BASE_DIR:-"$SCRIPT_DIR/../runtime"}

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

echo "[INFO] Supervisor started in Multi-VLAN TAP Mode."
echo "[INFO] Monitoring interface '$INTERFACE' for Modbus traffic on port 502."

# ─── Main Loop ────────────────────────────────────────────────

while true; do
  TS=$(date +%Y%m%d_%H%M%S)
  PCAP="$PCAP_DIR/segment_${TS}.pcap"

  echo "[+] [$TS] Starting capture for $CAPTURE_DURATION seconds -> $PCAP"
  timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -s "$PCAP_SNAPLEN" -w "$PCAP" 'vlan and port 502' &
  CAPTURE_PID=$!

  if [[ -n "$LAST_PCAP" && -f "$LAST_PCAP" ]]; then
    (
      LAST_TS=$(basename "$LAST_PCAP" .pcap | cut -d'_' -f2-)
      LAST_SEGMENT_DIR="$ZEEK_LOG_DIR/segment_$LAST_TS"
      LAST_ALERT_FILE="$ALERT_DIR/alerts_$LAST_TS.json"
      VLAN_MAP_FILE="$VLAN_LOG_DIR/vlan_map_$LAST_TS.log"
      mkdir -p "$LAST_SEGMENT_DIR"

      echo "[+] [$LAST_TS] Analyzing previous capture: $LAST_PCAP"

      # 1. Zeek Deep Modbus Parsing
      echo "  [-] Running Zeek analysis..."
      (cd "$LAST_SEGMENT_DIR" && "$ZEEK_BIN" -Cr "$LAST_PCAP" "$PLUGIN_DIR" >/dev/null 2>&1)

      if [[ -f "$LAST_SEGMENT_DIR/modbus_detailed.log" ]]; then
        # 2. Generate UID-to-VLAN Map
        echo "  [-] Creating VLAN map for each transaction..."
        tshark -r "$LAST_PCAP" -Y "modbus" -T fields -e zeek.uid -e vlan.id | sort -u > "$VLAN_MAP_FILE"

        # 3. Run Detection Engine
        echo "  [-] Running context-aware detection..."
        "$PYTHON_BIN" "$DETECT_SCRIPT" \
          --log "$LAST_SEGMENT_DIR/modbus_detailed.log" \
          --policy "$POLICY_FILE" \
          --addrmap "$ADDR_MAP" \
          --vlan-map "$VLAN_MAP_FILE" \
          --out "$LAST_ALERT_FILE"

        # 4. Optionally: Build Incident Report
        if [[ -s "$LAST_ALERT_FILE" ]]; then
          echo "  [-] Generating incident report..."
          "$PYTHON_BIN" "$INCIDENT_SCRIPT" \
            --alerts "$LAST_ALERT_FILE" \
            --out "$INCIDENT_DIR/incident_$LAST_TS.json"
        fi
      else
        echo "[!] [$LAST_TS] No modbus_detailed.log found for $LAST_PCAP"
      fi
    ) &
  fi

  wait "$CAPTURE_PID"

  if [[ ! -s "$PCAP" ]]; then
    echo "[!] [$TS] Capture file is empty. Skipping."
    rm -f "$PCAP"
    LAST_PCAP=""
  else
    echo "[OK] [$TS] Finished capture: $PCAP ($(du -h "$PCAP" | cut -f1))"
    LAST_PCAP="$PCAP"
  fi

  # ... (Optional housekeeping: purge old files, enforce retention, etc.) ...
done

