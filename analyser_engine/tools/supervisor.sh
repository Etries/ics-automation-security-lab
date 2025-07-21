#!/usr/bin/env bash

# ... (all variable definitions remain the same) ...

# Create runtime directories
# ... (same as before) ...

trap "echo 'Shutting down...'; kill 0; exit 0" SIGINT SIGTERM

LAST_PCAP=""
echo "[INFO] Supervisor started in Multi-VLAN TAP Mode."
echo "[INFO] Monitoring interface '$INTERFACE' for Modbus traffic on port 502."

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

      # 1. Run Zeek for deep Modbus parsing
      echo "  [-] Running Zeek analysis..."
      (cd "$LAST_SEGMENT_DIR" && "$ZEEK_BIN" -Cr "$LAST_PCAP" "$PLUGIN_DIR" >/dev/null 2>&1)

      if [[ -f "$LAST_SEGMENT_DIR/modbus_detailed.log" ]]; then
        # 2. Use tshark to create a UID-to-VLAN mapping file.
        # This tells us which VLAN each specific Modbus transaction was on.
        echo "  [-] Creating VLAN map for each transaction..."
        tshark -r "$LAST_PCAP" -Y "modbus" -T fields -e zeek.uid -e vlan.id | sort -u > "$VLAN_MAP_FILE"
        
        # 3. Run the context-aware detection script, now providing the VLAN map
        echo "  [-] Running context-aware detection script..."
        "$PYTHON_BIN" "$DETECT_SCRIPT" \
          --log "$LAST_SEGMENT_DIR/modbus_detailed.log" \
          --policy "$POLICY_FILE" \
          --addrmap "$ADDR_MAP" \
          --vlan-map "$VLAN_MAP_FILE" \
          --out "$LAST_ALERT_FILE"
      else
        echo "[!] [$LAST_TS] No modbus_detailed.log found for $LAST_PCAP."
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

  # ... (Housekeeping remains the same) ...
done
