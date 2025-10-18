#!/usr/bin/env bash
set -euo pipefail
DNS=${DNS:-10.20.0.1}
END=$((SECONDS+3600))
UA="CorpDS/1.0"
APIS=( "https://httpbin.org/bytes/512" "https://httpbin.org/json" "https://httpbin.org/delay/1" )
PYPI=( "https://pypi.org/simple/pandas/" "https://pypi.org/simple/numpy/" "https://pypi.org/simple/scikit-learn/" )
DOCS=( "https://docs.python.org/3/library/random.html" "https://www.rfc-editor.org/rfc/rfc9110" )

rand(){ awk 'BEGIN{srand();printf "%.2f\n", 0.1+rand()*0.8}'; }

while [ $SECONDS -lt $END ]; do
  dig +timeout=2 ds$RANDOM.lab.example @${DNS} >/dev/null 2>&1 || true

  curl -s --max-time 8 -A "$UA" "${APIS[$RANDOM%${#APIS[@]}]}" >/dev/null || true
  curl -s --max-time 8 -A "$UA" "${DOCS[$RANDOM%${#DOCS[@]}]}" >/dev/null || true

  curl -sI --max-time 6 -A "$UA" "${PYPI[$RANDOM%${#PYPI[@]}]}" >/dev/null || true

  if ((RANDOM%15==0)); then
    timeout 3 bash -lc 'echo QUIT | openssl s_client -connect 1.1.1.1:853 -quiet' >/dev/null 2>&1 || true
    curl -sS --max-time 3 https://1.1.1.1/dns-query >/dev/null 2>&1 || true
  fi

  sleep "$(rand)"
done
