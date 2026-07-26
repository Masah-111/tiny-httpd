#!/usr/bin/env bash
# tiny-httpd 統合テスト（Linux / macOS / WSL）。
#   使い方: tests/run_tests.sh          … portable(pthread) 版をビルドしてテスト
#           USE_EPOLL=1 tests/run_tests.sh … epoll 版をビルドしてテスト
# 依存: gcc, curl, python3
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PORT="${PORT:-8971}"
BIN="$(mktemp -u /tmp/tinyhttpd.XXXXXX)"
FIX="$ROOT/www/__test20.bin"

# --- ビルド ---
CFLAGS="-Wall -Wextra -O2"
if [ "${USE_EPOLL:-0}" = "1" ]; then
    echo "building epoll edition..."; gcc server.c -o "$BIN" -DUSE_EPOLL -lpthread $CFLAGS || exit 2
else
    echo "building portable edition..."; gcc server.c -o "$BIN" -lpthread $CFLAGS || exit 2
fi

# --- フィクスチャ（20バイトの既知データ）---
printf '0123456789ABCDEFGHIJ' > "$FIX"

# --- サーバ起動 ---
"$BIN" "$PORT" > /tmp/tinyhttpd_test.log 2>&1 &
SRV=$!
cleanup() { kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; rm -f "$FIX" "$BIN"; }
trap cleanup EXIT
sleep 0.5
if ! kill -0 "$SRV" 2>/dev/null; then echo "SERVER FAILED TO START"; cat /tmp/tinyhttpd_test.log; exit 2; fi

PASS=0; FAIL=0
U="http://127.0.0.1:$PORT"
check() { # desc expected actual
  if [ "$2" = "$3" ]; then printf "  PASS  %-38s\n" "$1"; PASS=$((PASS+1));
  else printf "  FAIL  %-38s (expected %s, got %s)\n" "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }
# 生ソケットで1行目のステータスコードを取る（curl が正規化する経路の検証用）
raw_status() { python3 - "$PORT" "$1" <<'PY'
import socket,sys
port=int(sys.argv[1])
# リテラルの \r\n を本物の CRLF に展開してから送る
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
BODY="$(curl -s -d 'ping123' $U/echo)"
check "POST /echo body     echoes" "ping123" "$BODY"

echo "== methods =="
check "OPTIONS /           -> 204" 204 "$(code -X OPTIONS $U/)"
check "PUT /               -> 405" 405 "$(code -X PUT $U/)"

echo "== security =="
check "traversal ../       -> 403" 403 "$(raw_status 'GET /../server.c HTTP/1.1\r\nHost: x\r\n\r\n')"
check "null %00            -> 400" 400 "$(raw_status 'GET /a%00.html HTTP/1.1\r\nHost: x\r\n\r\n')"
check "Transfer-Encoding   -> 400" 400 "$(code -H 'Transfer-Encoding: chunked' -X POST $U/echo)"
BIG="$(head -c 2000000 /dev/zero | curl -s -o /dev/null -w '%{http_code}' --data-binary @- $U/echo)"
check "body 2MB            -> 413" 413 "$BIG"

echo "== parse hardening =="
check "HTTP/2.0            -> 505" 505 "$(raw_status 'GET / HTTP/2.0\r\nHost: x\r\n\r\n')"
check "bad method          -> 400" 400 "$(raw_status 'ge!t / HTTP/1.1\r\nHost: x\r\n\r\n')"
check "obs-fold            -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\nH: x\r\n y\r\n\r\n')"
check "no-colon header     -> 400" 400 "$(raw_status 'GET / HTTP/1.1\r\nBadHeader\r\n\r\n')"

echo "== cache =="
ETAG="$(curl -sI $U/__test20.bin | grep -i '^etag' | sed 's/[Ee][Tt]ag: //' | tr -d '\r')"
check "If-None-Match etag  -> 304" 304 "$(code -H "If-None-Match: $ETAG" $U/__test20.bin)"
check "IMS future date     -> 304" 304 "$(code -H 'If-Modified-Since: Fri, 01 Jan 2100 00:00:00 GMT' $U/__test20.bin)"
check "IMS past date       -> 200" 200 "$(code -H 'If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT' $U/__test20.bin)"
CC="$(curl -sI $U/__test20.bin | grep -ci '^cache-control')"
check "Cache-Control set   -> 1"   1   "$CC"

echo "== range =="
check "single range 0-4    -> 206" 206 "$(code -H 'Range: bytes=0-4' $U/__test20.bin)"
check "unsatisfiable       -> 416" 416 "$(code -H 'Range: bytes=999-1000' $U/__test20.bin)"
check "malformed(ignored)  -> 200" 200 "$(code -H 'Range: bytes=zzz' $U/__test20.bin)"
MULTI="$(curl -s -D - -o /dev/null -H 'Range: bytes=0-4,10-14' $U/__test20.bin | grep -ci 'multipart/byteranges')"
check "multi-range multipart -> 1" 1 "$MULTI"
IFRBAD="$(code -H 'If-Range: "nope-0"' -H 'Range: bytes=0-4' $U/__test20.bin)"
check "If-Range mismatch   -> 200" 200 "$IFRBAD"

echo ""
echo "==================================================="
echo "  RESULT: $PASS passed, $FAIL failed"
echo "==================================================="
[ "$FAIL" -eq 0 ]
