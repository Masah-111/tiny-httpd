#!/usr/bin/env bash
# tiny-httpd 統合テスト（Linux / macOS / WSL）。
#   使い方: tests/run_tests.sh              … portable(pthread) 版
#           USE_EPOLL=1 tests/run_tests.sh  … epoll 版
#           BIN=/path/to/server tests/run_tests.sh … 既存バイナリを使う（ASan 版など）
# 依存: gcc, curl, python3
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PORT="${PORT:-8971}"
FIX="$ROOT/www/__test20.bin"
SUBDIR="$ROOT/www/__testdir"

# --- ビルド（BIN が指定されていればそれを使う）---
CFLAGS="-Wall -Wextra -O2"
HAVE_GZIP=0
if [ -n "${BIN:-}" ]; then
    echo "using existing binary: $BIN"
    # 既存バイナリが gzip 対応かは分からないので、GZIP=1 が指定されたときだけ検証する
    [ "${GZIP:-0}" = "1" ] && HAVE_GZIP=1
else
    BIN="$(mktemp -u /tmp/tinyhttpd.XXXXXX)"
    GZFLAGS=""
    if [ -f /usr/include/zlib.h ]; then GZFLAGS="-DUSE_GZIP -lz"; HAVE_GZIP=1; fi
    if [ "${USE_EPOLL:-0}" = "1" ]; then
        echo "building epoll edition..."
        # shellcheck disable=SC2086
        gcc server.c -o "$BIN" -DUSE_EPOLL $GZFLAGS -lpthread $CFLAGS || exit 2
    else
        echo "building portable edition..."
        # shellcheck disable=SC2086
        gcc server.c -o "$BIN" $GZFLAGS -lpthread $CFLAGS || exit 2
    fi
    BUILT=1
fi

# --- フィクスチャ ---
printf '0123456789ABCDEFGHIJ' > "$FIX"
mkdir -p "$SUBDIR"
echo "sub-directory-file" > "$SUBDIR/file.txt"
python3 -c "open('$ROOT/www/__big.txt','w').write('tiny-httpd compressible line\n'*400)"

# --- サーバ起動（レート制限はテストを妨げないよう緩めに）---
TINYHTTPD_BURST=100000 TINYHTTPD_RATE=100000 "$BIN" "$PORT" > /tmp/tinyhttpd_test.log 2>&1 &
SRV=$!
cleanup() {
    kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
    rm -rf "$FIX" "$SUBDIR" "$ROOT/www/__big.txt"
    [ "${BUILT:-0}" = "1" ] && rm -f "$BIN"
    return 0
}
trap cleanup EXIT
sleep 0.6
if ! kill -0 "$SRV" 2>/dev/null; then echo "SERVER FAILED TO START"; cat /tmp/tinyhttpd_test.log; exit 2; fi

PASS=0; FAIL=0
U="http://127.0.0.1:$PORT"
check() {
  if [ "$2" = "$3" ]; then printf "  PASS  %-38s\n" "$1"; PASS=$((PASS+1));
  else printf "  FAIL  %-38s (expected %s, got %s)\n" "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
raw_status() { python3 - "$PORT" "$1" <<'PY'
import socket,sys
port=int(sys.argv[1])
req=sys.argv[2].encode().decode('unicode_escape').encode('latin-1')
s=socket.create_connection(("127.0.0.1",port)); s.sendall(req)
d=s.recv(128).split(b" ")
print(d[1].decode() if len(d)>1 else "ERR")
PY
}

echo "== core =="
check "GET /               -> 200" 200 "$(code $U/)"
check "GET /missing        -> 404" 404 "$(code $U/nope.html)"
check "GET /test           -> 200" 200 "$(code $U/__test20.bin)"
check "POST /echo body     echoes" "ping123" "$(curl -s -d 'ping123' $U/echo)"
check "HEAD /              -> 200" 200 "$(code -I $U/)"

echo "== methods =="
check "OPTIONS /           -> 204" 204 "$(code -X OPTIONS $U/)"
check "PUT /               -> 405" 405 "$(code -X PUT $U/)"
check "405 sends Allow     -> 1"   1   "$(curl -s -D - -o /dev/null -X PUT $U/ | grep -ci '^allow')"

echo "== security =="
check "traversal ../       -> 403" 403 "$(raw_status 'GET /../server.c HTTP/1.1\r\nHost: x\r\n\r\n')"
check "encoded ..%2f       -> 403" 403 "$(raw_status 'GET /..%2fserver.c HTTP/1.1\r\nHost: x\r\n\r\n')"
check "null %00            -> 400" 400 "$(raw_status 'GET /a%00.html HTTP/1.1\r\nHost: x\r\n\r\n')"
check "TE + CL (smuggling) -> 400" 400 "$(raw_status 'POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n')"
check "TE: gzip            -> 501" 501 "$(raw_status 'POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n')"
BIG="$(head -c 2000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' --data-binary @- $U/echo)"
check "body 2MB            -> 413" 413 "$BIG"

echo "== protocol version / Host =="
check "HTTP/1.0 no Host    -> 200" 200 "$(raw_status 'GET / HTTP/1.0\r\n\r\n')"
check "HTTP/1.1 no Host    -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\n\r\n')"
check "duplicate Host      -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n')"
check "HTTP/3.0            -> 505" 505 "$(raw_status 'GET / HTTP/3.0\r\nHost: x\r\n\r\n')"

echo "== parse hardening =="
check "HTTP/2.0            -> 505" 505 "$(raw_status 'GET / HTTP/2.0\r\nHost: x\r\n\r\n')"
check "bad method          -> 400" 400 "$(raw_status 'ge!t / HTTP/1.1\r\nHost: x\r\n\r\n')"
check "obs-fold            -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\nH: x\r\n y\r\n\r\n')"
check "no-colon header     -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\nBadHeader\r\n\r\n')"

echo "== chunked bodies =="
check "chunked echo        roundtrip" "chunked-ok" "$(curl -s -H 'Transfer-Encoding: chunked' -d 'chunked-ok' $U/echo)"
python3 -c "print('y'*9000)" > /tmp/tinyhttpd_big_chunk.txt
check "chunked 9KB         roundtrip" "9001" "$(curl -s -H 'Transfer-Encoding: chunked' --data-binary @/tmp/tinyhttpd_big_chunk.txt $U/echo | wc -c | tr -d ' ')"
rm -f /tmp/tinyhttpd_big_chunk.txt
check "bad chunk size      -> 400" 400 "$(raw_status 'POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\n')"

echo "== directories =="
check "dir without slash   -> 301" 301 "$(code $U/__testdir)"
check "dir listing off     -> 403" 403 "$(code $U/__testdir/)"

echo "== cache =="
ETAG="$(curl -sI $U/__test20.bin | grep -i '^etag' | sed 's/[Ee][Tt]ag: //' | tr -d '\r')"
check "If-None-Match etag  -> 304" 304 "$(code -H "If-None-Match: $ETAG" $U/__test20.bin)"
check "IMS future date     -> 304" 304 "$(code -H 'If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT' $U/__test20.bin)"
check "IMS past date       -> 200" 200 "$(code -H 'If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT' $U/__test20.bin)"
check "Cache-Control set   -> 1"   1   "$(curl -sI $U/__test20.bin | grep -ci '^cache-control')"
check "Expires set         -> 1"   1   "$(curl -sI $U/__test20.bin | grep -ci '^expires')"

echo "== range =="
check "single range 0-4    -> 206" 206 "$(code -H 'Range: bytes=0-4' $U/__test20.bin)"
check "range content       -> 56789" "56789" "$(curl -s -r 5-9 $U/__test20.bin)"
check "unsatisfiable       -> 416" 416 "$(code -H 'Range: bytes=999-1000' $U/__test20.bin)"
check "malformed(ignored)  -> 200" 200 "$(code -H 'Range: bytes=zzz' $U/__test20.bin)"
check "multi-range multipart -> 1" 1 "$(curl -s -D - -o /dev/null -H 'Range: bytes=0-4,10-14' $U/__test20.bin | grep -ci 'multipart/byteranges')"
check "If-Range mismatch   -> 200" 200 "$(code -H 'If-Range: "nope-0"' -H 'Range: bytes=0-4' $U/__test20.bin)"

echo "== ipv6 =="
if curl -s -6 -o /dev/null "http://[::1]:$PORT/" 2>/dev/null; then
  check "IPv6 [::1]          -> 200" 200 "$(code -6 "http://[::1]:$PORT/")"
else
  echo "  SKIP  IPv6 (no ::1 on this host)"
fi

if [ "$HAVE_GZIP" = "1" ]; then
echo "== gzip =="
check "gzip encoding       -> 1" 1 "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $U/__big.txt | grep -ci '^content-encoding: gzip')"
check "Vary header         -> 1" 1 "$(curl -sI $U/__big.txt | grep -ci '^vary')"
check "gzip decompresses   ok" "ok" "$(curl -s -H 'Accept-Encoding: gzip' --output - $U/__big.txt | python3 -c "
import gzip,sys
d=gzip.decompress(sys.stdin.buffer.read())
print('ok' if d.count(b'compressible')==400 else 'bad')")"
check "gzip ETag differs   -> 1" 1 "$( [ "$(curl -sI $U/__big.txt | grep -i '^etag')" != "$(curl -sI -H 'Accept-Encoding: gzip' $U/__big.txt | grep -i '^etag')" ] && echo 1 || echo 0)"
check "binary not gzipped  -> 0" 0 "$(curl -s -D - -o /dev/null -H 'Accept-Encoding: gzip' $U/__test20.bin | grep -ci '^content-encoding')"
fi

echo "== rate limiting =="
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
TINYHTTPD_BURST=3 TINYHTTPD_RATE=0 "$BIN" "$((PORT+1))" > /tmp/tinyhttpd_rl.log 2>&1 &
SRV=$!
sleep 0.5
RL="$U"; RL="http://127.0.0.1:$((PORT+1))"
for _ in 1 2 3; do curl -s -o /dev/null "$RL/" ; done
check "over burst          -> 429" 429 "$(code $RL/)"
check "429 has Retry-After -> 1"   1   "$(curl -s -D - -o /dev/null $RL/ | grep -ci '^retry-after')"

echo ""
echo "==================================================="
echo "  RESULT: $PASS passed, $FAIL failed"
echo "==================================================="
[ "$FAIL" -eq 0 ]
