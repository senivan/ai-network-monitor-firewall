#!/usr/bin/env bash
set -euo pipefail
DNS=${DNS:-10.20.0.1}
END=$((SECONDS+3600))
UA="CorpITOps/1.0"

command -v python3 >/dev/null && nohup bash -c 'cd /tmp && python3 -m http.server 8080' >/dev/null 2>&1 &
command -v iperf3   >/dev/null && iperf3 -s -D || true

rand(){ awk 'BEGIN{srand();printf "%.2f\n", 0.2+rand()*1.0}'; }

while [ $SECONDS -lt $END ]; do
  dig +timeout=2 host$RANDOM.ops.example @${DNS} >/dev/null 2>&1 || true
  ping -c1 -W1 10.20.0.1 >/dev/null 2>&1 || true

  curl -s --max-time 8 -A "$UA" https://httpbin.org/ip >/dev/null || true
  curl -s --max-time 8 -A "$UA" https://www.iana.org/time-zones >/dev/null || true

  for p in 22 80 443 445 3389 5353; do
    nc -z -w1 10.20.0.1 $p 2>/dev/null || true
  done


  sleep "$(rand)"
done

pkill -f "python3 -m http.server" >/dev/null 2>&1 || true
