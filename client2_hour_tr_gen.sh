#!/usr/bin/env bash
set -euo pipefail
DNS=${DNS:-10.20.0.1}
END=$((SECONDS+3600))
UA="CorpDevOps/1.0"
DOCS=( "https://kernel.org" "https://git-scm.com" "https://docs.python.org/3/" "https://httpbin.org/headers" )
PKG_URLS=( "http://deb.debian.org/debian/dists/bookworm/Release"
           "http://security.debian.org/debian-security/dists/bookworm-security/Release" )
LONG_DL="https://speed.hetzner.de/100MB.bin"

rand(){ awk 'BEGIN{srand();printf "%.2f\n", 0.15+rand()*0.9}'; }

while [ $SECONDS -lt $END ]; do
  dig +timeout=2 devops$RANDOM.internal @${DNS} >/dev/null 2>&1 || true
  curl -s --max-time 8 -A "$UA" "${DOCS[$RANDOM%${#DOCS[@]}]}" >/dev/null || true

  curl -s --max-time 6 -A "$UA" "${PKG_URLS[$RANDOM%${#PKG_URLS[@]}]}" >/dev/null || true

  if ((RANDOM%12==0)); then
    curl -s --max-time 25 --limit-rate 300k -A "$UA" -L "$LONG_DL" -o /tmp/dev_$RANDOM.bin || true
  fi

  nc -z -w1 10.20.0.1 22 80 443 853 5353 2>/dev/null || true

  sleep "$(rand)"
done
