#!/usr/bin/env bash
# vps_iptest.sh -- Ubuntu 22.x
# Starts minimal test listeners on :80 (HTTP) and :443 (TLS) + writes a brief report.

set -euo pipefail

WORKDIR="/opt/iptest"
HTTP_PID="/run/iptest_http80.pid"
TLS_PID="/run/iptest_tls443.pid"
HTTP_LOG="/tmp/iptest_http80.log"
TLS_LOG="/tmp/iptest_tls443.log"
REPORT="$WORKDIR/report.txt"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }

allow_ports() {
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow 80/tcp || true
    sudo ufw allow 443/tcp || true
    sudo ufw status || true
  fi
}

ensure_tools() {
  sudo apt-get update -y
  sudo apt-get install -y python3 openssl curl
  need_cmd python3
  need_cmd openssl
  need_cmd curl
}

start_services() {
  sudo mkdir -p "$WORKDIR"
  cd /
  cd "$WORKDIR"

  echo "OK" | sudo tee "$WORKDIR/index.html" >/dev/null

  # HTTP on :80
  if [ -f "$HTTP_PID" ] && ps -p "$(cat "$HTTP_PID")" >/dev/null 2>&1; then
    echo "HTTP server already running (pid $(cat "$HTTP_PID"))."
  else
    sudo nohup python3 -m http.server 80 > "$HTTP_LOG" 2>&1 &
    echo $! | sudo tee "$HTTP_PID" >/dev/null
  fi

  # Self-signed cert + TLS on :443 (with ALPN for h2/http1.1)
  if [ ! -f "$WORKDIR/key.pem" ] || [ ! -f "$WORKDIR/cert.pem" ]; then
    sudo openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=test.local"
  fi
  if [ -f "$TLS_PID" ] && ps -p "$(cat "$TLS_PID")" >/dev/null 2>&1; then
    echo "TLS test server already running (pid $(cat "$TLS_PID"))."
  else
    sudo nohup openssl s_server -accept 443 -cert cert.pem -key key.pem -www -alpn h2,http/1.1 > "$TLS_LOG" 2>&1 &
    echo $! | sudo tee "$TLS_PID" >/dev/null
  fi
}

status_services() {
  echo "=== LISTEN status (ss) ==="
  sudo ss -ltn 'sport = :80 or sport = :443' || true
}

self_tests() {
  sudo mkdir -p "$WORKDIR"
  echo "=== Local loopback tests ===" | sudo tee "$REPORT" >/dev/null
  (curl -I --max-time 5 http://127.0.0.1/ 2>&1 || true) | sudo tee -a "$REPORT" >/dev/null
  (echo | openssl s_client -connect 127.0.0.1:443 -brief 2>&1 || true) | sudo tee -a "$REPORT" >/dev/null
  echo -e "\nReport saved: $REPORT"
}

stop_services() {
  sudo bash -c '
    kill $(cat '"$HTTP_PID"') 2>/dev/null || true
    kill $(cat '"$TLS_PID"') 2>/dev/null || true
    rm -f '"$HTTP_PID"' '"$TLS_PID"' '"$HTTP_LOG"' '"$TLS_LOG"'
  '
  echo "Stopped. Remove $WORKDIR if you want: sudo rm -rf $WORKDIR"
}

case "${1:-start}" in
  start)
    allow_ports
    ensure_tools
    start_services
    status_services
    self_tests
    ;;
  status) status_services ;;
  stop)   stop_services ;;
  *) echo "Usage: sudo $0 {start|status|stop}"; exit 1 ;;
esac
