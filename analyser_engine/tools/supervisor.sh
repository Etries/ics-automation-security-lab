#!/usr/bin/env bash

# ─────────────────────────────
# ICS Supervisor Pipeline (Hybrid, Parallel Capture/Analysis)
# ─────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../config"
DETECT_SCRIPT="$SCRIPT_DIR/detect.py"
INCIDENT_SCRIPT="$SCRIPT_DIR/incident_builder.py"
POLICY_FILE="$CONFIG_DIR/policy.yaml"
ADDR_MAP="$CONFIG_DIR/addr_map.yaml"
CONF_FILE="$CONFIG_DIR/supervisor.conf"

if [[ "$EUID" -ne 0 ]]; then
  echo "[!] This script must be run as root. Trying with sudo..."
  exec sudo "$0" "$@"
fi

echo "Running as user: $(whoami)"

# Load user-defined config
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE"

BASE_DIR="${BASE_DIR:-$SCRIPT_DIR/../runtime}"

ZEEK_BIN=${ZEEK_BIN:-"/opt/zeek/bin/zeek"}
INTERFACE=${INTERFACE:-"eth0"}
CAPTURE_DURATION=${CAPTURE_DURATION:-30}
PCAP_SNAPLEN=${PCAP_SNAPLEN:-65535}
PCAP_SIZE_LIMIT_MB=${PCAP_SIZE_LIMIT_MB:-10}
PLUGIN_DIR=${PLUGIN_DIR:-"/home/kali/.zkg/clones/package/icsnpp-modbus/scripts"}
RETENTION_MINUTES=${RETENTION_MINUTES:-60}
PYTHON="python3"

# Handle CLI overrides
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --interface) INTERFACE="$2"; shift ;;
    --duration) CAPTURE_DURATION="$2"; shift ;;
    --snaplen) PCAP_SNAPLEN="$2"; shift ;;
    --size-limit) PCAP_SIZE_LIMIT_MB="$2"; shift ;;
    --base-dir) BASE_DIR="$2"; shift ;;
    *) echo "[!] Unknown option $1"; exit 1 ;;
  esac
  shift
done

# Validate Zeek plugin
if [[ ! -d "$PLUGIN_DIR" ]]; then
  echo "[FATAL] Zeek plugin dir not found: $PLUGIN_DIR"
  exit 1
fi

# Create runtime directories
ZEEK_LOG_DIR="$BASE_DIR/zeek_logs"
VLAN_LOG_DIR="$BASE_DIR/vlan_logs"
ALERT_DIR="$BASE_DIR/alerts"
INCIDENT_DIR="$BASE_DIR/incidents"
ARCHIVE_DIR="$BASE_DIR/archive"
PCAP_DIR="$BASE_DIR/pcaps"
mkdir -p "$ZEEK_LOG_DIR" "$VLAN_LOG_DIR" "$ALERT_DIR" "$INCIDENT_DIR" "$ARCHIVE_DIR" "$PCAP_DIR"

# Tool availability checks
command -v tcpdump >/dev/null 2>&1 || { echo "tcpdump not found!"; exit 1; }
command -v "$ZEEK_BIN" >/dev/null 2>&1 || { echo "Zeek not found!"; exit 1; }
command -v tshark >/dev/null 2>&1 || { echo "tshark not found!"; exit 1; }
command -v "$PYTHON" >/dev/null 2>&1 || { echo "Python not found!"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not found!"; exit 1; }

# Optional: Centralized logging (uncomment to enable)
# LOGFILE="$BASE_DIR/supervisor.log"
# exec > >(tee -a "$LOGFILE") 2>&1

# Graceful shutdown
trap "echo 'Shutting down...'; exit 0" SIGINT SIGTERM

LAST_PCAP=""

while true; do
  TS=$(date +%Y%m%d_%H%M%S)
  PCAP="$PCAP_DIR/segment_${TS}.pcap"
  SEGMENT_DIR="$ZEEK_LOG_DIR/segment_$TS"
  mkdir -p "$SEGMENT_DIR"
  ALERT_FILE="$ALERT_DIR/alerts_$TS.json"
  INCIDENT_FILE="$INCIDENT_DIR/incident_report_$TS.json"
  VLAN_OUT="$VLAN_LOG_DIR/vlan_$TS.txt"

  echo "[+][$TS] Starting capture for $CAPTURE_DURATION seconds → $PCAP"
  timeout "$CAPTURE_DURATION" tcpdump -i "$INTERFACE" -s "$PCAP_SNAPLEN" -w "$PCAP" vlan and port 502 &
  CAPTURE_PID=$!

  # Analyze previous PCAP while capturing
  if [[ -n "$LAST_PCAP" && -f "$LAST_PCAP" ]]; then
    LAST_TS=$(basename "$LAST_PCAP" | sed 's/segment_\(.*\)\.pcap/\1/')
    LAST_SEGMENT_DIR="$ZEEK_LOG_DIR/segment_${LAST_TS}"
    LAST_ALERT_FILE="$ALERT_DIR/alerts_${LAST_TS}.json"
    mkdir -p "$LAST_SEGMENT_DIR"
    ABS_PCAP=$(readlink -f "$LAST_PCAP")
    echo "[+][$LAST_TS] Running Zeek analysis on $ABS_PCAP..."
    (
      cd "$LAST_SEGMENT_DIR"
      "$ZEEK_BIN" -Cr "$ABS_PCAP" "$PLUGIN_DIR"
    )
    if [[ -f "$LAST_SEGMENT_DIR/modbus_detailed.log" ]]; then
      echo "[+][$LAST_TS] VLAN tag analysis with tshark..."
      tshark -r "$ABS_PCAP" -Y "vlan" -T fields -e vlan.id > "$VLAN_LOG_DIR/vlan_$LAST_TS.txt"
      VLAN_LIST=$(sort "$VLAN_LOG_DIR/vlan_$LAST_TS.txt" | uniq | paste -sd ',' -)
      VLAN_COUNT=$(echo "$VLAN_LIST" | awk -F',' '{print NF}')
      VLAN_ALERT_JSON=""
      if (( VLAN_COUNT > 1 )); then
        VLAN_ALERT_JSON="{ \"rule_id\": \"VLAN_HOPPING_DETECTED\", \"severity\": \"High\", \"timestamp\": \"$LAST_TS\", \"vlans\": \"$VLAN_LIST\", \"reason\": \"Multiple VLAN IDs seen in one capture\" }"
        echo "[ALERT][$LAST_TS] VLAN Hopping Detected: $VLAN_LIST"
      fi
      echo "[+][$LAST_TS] Running detect.py..."
      $PYTHON "$DETECT_SCRIPT" \
        --log "$LAST_SEGMENT_DIR/modbus_detailed.log" \
        --policy "$POLICY_FILE" \
        --addrmap "$ADDR_MAP" \
        --out "$LAST_ALERT_FILE"
      if [[ -n "$VLAN_ALERT_JSON" ]]; then
        if [[ -s "$LAST_ALERT_FILE" ]]; then
          tmp=$(mktemp)
          if jq ". + [${VLAN_ALERT_JSON}]" "$LAST_ALERT_FILE" > "$tmp"; then
            mv "$tmp" "$LAST_ALERT_FILE"
          else
            echo "[!] jq failed to merge VLAN alert. Appending as new array."
            echo "[${VLAN_ALERT_JSON}]" > "$LAST_ALERT_FILE"
          fi
        else
          echo "[${VLAN_ALERT_JSON}]" > "$LAST_ALERT_FILE"
        fi
      fi
      if [[ -s "$LAST_SEGMENT_DIR/notice.log" ]]; then
        cp "$LAST_SEGMENT_DIR/notice.log" "$LAST_SEGMENT_DIR/_notice_saved.log"
      fi
      if [[ -s "$LAST_SEGMENT_DIR/weird.log" ]]; then
        cp "$LAST_SEGMENT_DIR/weird.log" "$LAST_SEGMENT_DIR/_weird_saved.log"
        echo "[+][$LAST_TS] Weird traffic:"
        cat "$LAST_SEGMENT_DIR/weird.log"
      fi
      if [[ -s "$LAST_SEGMENT_DIR/conn.log" ]]; then
        grep "modbus" "$LAST_SEGMENT_DIR/conn.log" > "$LAST_SEGMENT_DIR/conn_modbus_only.log"
      fi
      CURRENT_MIN=$(date +%M)
      if [[ "$CURRENT_MIN" == "00" ]]; then
        echo "[+][$LAST_TS] Generating hourly incident report..."
        find "$ALERT_DIR" -type f -mmin -60 -name "alerts_*.json" -exec cat {} + > "$ALERT_DIR/_hour.json"
        $PYTHON "$INCIDENT_SCRIPT" \
          --alerts "$ALERT_DIR/_hour.json" \
          --out "$INCIDENT_FILE" \
          --window 3600
        rm -f "$ALERT_DIR/_hour.json"
      fi
    else
      echo "[!] Zeek failed or no modbus_detailed.log found for $LAST_TS"
    fi
  fi

  sleep "$CAPTURE_DURATION"
  wait "$CAPTURE_PID"

  if [[ ! -s "$PCAP" ]]; then
    echo "[!] PCAP $PCAP was not created or is empty. Skipping this cycle."
    rm -f "$PCAP"
    LAST_PCAP=""
    continue
  else
    echo "[OK] Captured $PCAP ($(du -h "$PCAP" | cut -f1))"
  fi

  LAST_PCAP="$PCAP"

  echo "[+][$TS] Purging old files..."
  find "$PCAP_DIR" -type f -name "*.pcap" -mmin +$RETENTION_MINUTES -delete
  find "$ZEEK_LOG_DIR" -type d -name "segment_*" -mmin +$RETENTION_MINUTES -exec rm -rf {} +
  find "$VLAN_LOG_DIR" -type f -mmin +$RETENTION_MINUTES -delete
  find "$ALERT_DIR" -type f -mmin +$RETENTION_MINUTES -delete
  find "$INCIDENT_DIR" -type f -mmin +$RETENTION_MINUTES -delete

done 
