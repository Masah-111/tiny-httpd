#!/usr/bin/env bash
# ランダム・不正なリクエストを大量に投げ、サーバが落ちないことを確認する。
# ASan/UBSan つきでビルドしたバイナリに対して実行すると、メモリ破壊や未定義動作も検出できる。
#
#   tests/fuzz.sh              … 通常ビルドに対して 2000 回
#   ITER=5000 tests/fuzz.sh    … 回数を指定
#   BIN=./server_asan tests/fuzz.sh … ASan ビルドに対して実行
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PORT="${PORT:-8975}"
ITER="${ITER:-2000}"

if [ -n "${BIN:-}" ]; then
    echo "using existing binary: $BIN"
else
    BIN="$(mktemp -u /tmp/tinyfuzz.XXXXXX)"
    gcc server.c -o "$BIN" -lpthread -Wall -Wextra -O1 -g || exit 2
    BUILT=1
fi

"$BIN" "$PORT" > /tmp/tinyhttpd_fuzz.log 2>&1 &
SRV=$!
cleanup() {
    kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
    [ "${BUILT:-0}" = "1" ] && rm -f "$BIN"
    return 0
}
trap cleanup EXIT
sleep 0.6
if ! kill -0 "$SRV" 2>/dev/null; then echo "SERVER FAILED TO START"; cat /tmp/tinyhttpd_fuzz.log; exit 2; fi

echo "fuzzing $ITER requests against port $PORT ..."
python3 - "$PORT" "$ITER" <<'PY'
import random, socket, sys, string

port, iters = int(sys.argv[1]), int(sys.argv[2])
methods = [b"GET", b"POST", b"HEAD", b"OPTIONS", b"PUT", b"\x01\x02", b"", b"G"*40]
paths   = [b"/", b"/index.html", b"/../etc/passwd", b"/%00", b"/%%%%", b"/" + b"A"*3000,
           b"/\xff\xfe", b"/?a=" + b"b"*500, b"//////", b"/.", b"/..%2f..%2f"]
vers    = [b"HTTP/1.1", b"HTTP/1.0", b"HTTP/9.9", b"HTTP/", b"XYZ", b""]
hdrs    = [b"Host: x", b"Content-Length: -1", b"Content-Length: 99999999999",
           b"Transfer-Encoding: chunked", b"Transfer-Encoding: chunked\r\nContent-Length: 5",
           b"Range: bytes=" + b"9"*40, b"Range: bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13",
           b"If-None-Match: " + b'"'*50, b"If-Modified-Since: not-a-date",
           b"Accept-Encoding: gzip", b"X: " + b"v"*7000, b":novalue", b"NoColon",
           b" leading-space", b"Connection: keep-alive", b"Connection: close"]
bodies  = [b"", b"hello", b"ZZZ\r\n", b"5\r\nabcde\r\n0\r\n\r\n", b"\x00"*100, b"A"*5000]

sent = errors = 0
for i in range(iters):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        parts = [random.choice(methods), b" ", random.choice(paths), b" ", random.choice(vers), b"\r\n"]
        for _ in range(random.randint(0, 6)):
            parts.append(random.choice(hdrs) + b"\r\n")
        parts.append(b"\r\n")
        parts.append(random.choice(bodies))
        req = b"".join(parts)
        if random.random() < 0.15:                       # たまに完全なランダムバイト列
            req = bytes(random.getrandbits(8) for _ in range(random.randint(1, 400)))
        s.sendall(req)
        if random.random() < 0.5:
            # 本文待ちで止まるリクエストもあるので、応答は短時間だけ待つ
            s.settimeout(0.3)
            try: s.recv(256)
            except Exception: pass
        s.close()
        sent += 1
    except Exception:
        errors += 1
print(f"  sent={sent} connect_errors={errors}")
PY

sleep 0.4
if kill -0 "$SRV" 2>/dev/null; then
    echo -n "  server still alive: yes | sanity check GET / -> "
    curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:$PORT/"
else
    echo "  FAIL: server died during fuzzing"
    tail -20 /tmp/tinyhttpd_fuzz.log
    exit 1
fi

# ASan/UBSan が何か検出していれば失敗にする
if grep -qiE "AddressSanitizer|runtime error|LeakSanitizer" /tmp/tinyhttpd_fuzz.log; then
    echo "  FAIL: sanitizer reported an issue"
    grep -iE -A5 "AddressSanitizer|runtime error|LeakSanitizer" /tmp/tinyhttpd_fuzz.log | head -40
    exit 1
fi
echo "  no crashes, no sanitizer reports"
