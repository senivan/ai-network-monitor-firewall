#!/usr/bin/env bash
set -euo pipefail
DNS=${DNS:-10.20.0.1}
END=$((SECONDS+3600))
UA="CorpSales/1.0"
SITES=( "https://www.wikipedia.org" "https://www.iana.org/domains/reserved"
        "https://httpbin.org/uuid" "https://httpbin.org/anything" )
IMAGES=( "https://picsum.photos/seed/$RANDOM/640/360" "https://picsum.photos/seed/$RANDOM/800/600" )
BIGFILE="https://speed.hetzner.de/100MB.bin"

rand(){ awk 'BEGIN{srand();printf "%.2f\n", 0.3+rand()*1.2}'; }

while [ $SECONDS -lt $END ]; do
  dig +timeout=2 client$RANDOM.sales.example @${DNS} >/dev/null 2>&1 || true

  curl -s --max-time 8 -A "$UA" "${SITES[$RANDOM%${#SITES[@]}]}" >/dev/null || true

  if ((RANDOM%5==0)); then
    curl -s --max-time 10 -A "$UA" "${IMAGES[$RANDOM%${#IMAGES[@]}]}" -o /tmp/slide_$RANDOM.jpg || true
  fi

  if ((RANDOM%20==0)); then
    curl -s --max-time 30 --limit-rate 400k -A "$UA" -L "$BIGFILE" -o /tmp/sales_$RANDOM.bin || true
  fi

  sleep "$(rand)"
done
