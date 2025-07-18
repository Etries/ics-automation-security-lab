#!/usr/bin/env bash
OUT="/home/kali/Desktop/Thesis_framework/ics-automation-security-lab/analyser_engine/runtime/pcaps/test-direct.pcap"
sudo tcpdump -i eth0 -c 5 -w "$OUT"

