#!/usr/bin/env bash
# 簡易ベンチマーク: 同時接続数を変えながらスループットとレイテンシを測る。
# 外部ツール（wrk 等）に依存せず python3 だけで動く。
#
#   tests/loadtest.sh                    … portable 版
#   USE_EPOLL=1 tests/loadtest.sh        … epoll(C10K) 版
#   CONNS=200 REQS=20000 tests/loadtest.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PORT="${PORT:-8977}"
CONNS="${CONNS:-50}"
REQS="${REQS:-5000}"

BIN="$(mktemp -u /tmp/tinyload.XXXXXX)"
if [ "${USE_EPOLL:-0}" = "1" ]; then
    gcc server.c -o "$BIN" -DUSE_EPOLL -lpthread -Wall -O2 || exit 2; EDITION="epoll + thread pool"
else
    gcc server.c -o "$BIN" -lpthread -Wall -O2 || exit 2;            EDITION="thread-per-connection"
fi

# レート制限はベンチの邪魔になるので無効化して起動
TINYHTTPD_BURST=0 "$BIN" "$PORT" > /tmp/tinyhttpd_load.log 2>&1 &
SRV=$!
cleanup() { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -f "$BIN"; return 0; }
trap cleanup EXIT
sleep 0.6
kill -0 "$SRV" 2>/dev/null || { echo "server failed to start"; cat /tmp/tinyhttpd_load.log; exit 2; }

echo "edition     : $EDITION"
echo "concurrency : $CONNS"
echo "requests    : $REQS"
echo ""

python3 - "$PORT" "$CONNS" "$REQS" <<'PY'
import socket, sys, threading, time

port, conns, total = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
per = max(1, total // conns)
REQ = b"GET / HTTP/1.1\r\nHost: b\r\nConnection: keep-alive\r\n\r\n"
lat, ok, fail = [], 0, 0
lock = threading.Lock()

def worker():
    global ok, fail
    mine = []
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        buf = b""
        for _ in range(per):
            t0 = time.perf_counter()
            s.sendall(REQ)
            # ヘッダ終端まで読み、Content-Length 分の本文を読み切る
            while b"\r\n\r\n" not in buf:
                d = s.recv(65536)
                if not d: raise ConnectionError
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            clen = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":")[1]); break
            while len(rest) < clen:
                d = s.recv(65536)
                if not d: raise ConnectionError
                rest += d
            buf = rest[clen:]
            mine.append((time.perf_counter() - t0) * 1000.0)
        s.close()
        with lock:
            lat.extend(mine); ok += len(mine)
    except Exception:
        with lock:
            lat.extend(mine); ok += len(mine); fail += 1

threads = [threading.Thread(target=worker) for _ in range(conns)]
t0 = time.perf_counter()
for t in threads: t.start()
for t in threads: t.join()
elapsed = time.perf_counter() - t0

lat.sort()
def pct(p): return lat[min(len(lat) - 1, int(len(lat) * p))] if lat else 0.0
print(f"  completed   : {ok} requests in {elapsed:.2f}s ({fail} connection failures)")
print(f"  throughput  : {ok/elapsed:,.0f} req/s")
if lat:
    print(f"  latency avg : {sum(lat)/len(lat):.3f} ms")
    print(f"  latency p50 : {pct(0.50):.3f} ms")
    print(f"  latency p95 : {pct(0.95):.3f} ms")
    print(f"  latency p99 : {pct(0.99):.3f} ms")
PY
