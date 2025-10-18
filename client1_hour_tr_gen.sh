#!/usr/bin/env bash
set -euo pipefail
DNS=${DNS:-10.20.0.1}
END=$((SECONDS+3600))
UA="CorpFinance/1.0"
SITES_HTTP=( "http://example.com" "http://httpbin.org/html" )
SITES_HTTPS=( "https://www.iana.org" "https://www.wikipedia.org" "https://www.mozilla.org" "https://httpbin.org/get" )
PDFS=( "https://www.iana.org/go/rfc793" "https://www.rfc-editor.org/rfc/rfc8941.pdf" )

rand(){ awk 'BEGIN{srand();printf "%.2f\n", 0.2+rand()*1.1}'; }

while [ $SECONDS -lt $END ]; do
  dig +timeout=2 +short finance$RANDOM.example @${DNS} >/dev/null 2>&1 || true

  curl -s --max-time 8 -A "$UA" "${SITES_HTTP[$RANDOM%${#SITES_HTTP[@]}]}" >/dev/null || true
  curl -s --max-time 8 -A "$UA" "${SITES_HTTPS[$RANDOM%${#SITES_HTTPS[@]}]}" >/dev/null || true

  if ((RANDOM%10==0)); then
    curl -s --max-time 15 -A "$UA" -L "${PDFS[$RANDOM%${#PDFS[@]}]}" -o /tmp/fin_$RANDOM.pdf || true
  fi

  ping -c1 -W1 10.20.0.1 >/dev/null 2>&1 || true

  sleep "$(rand)"
done
