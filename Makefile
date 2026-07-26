# tiny-httpd — build targets
#
#   make              … 標準版（thread-per-connection）
#   make epoll        … C10K 版（epoll + スレッドプール / Linux 専用）
#   make tls          … TLS 版（要 OpenSSL）
#   make gzip         … gzip 圧縮つき（要 zlib）
#   make all-variants … 上記をまとめてビルド（CI 用）
#   make test         … 統合テスト（標準版）
#   make test-epoll   … 統合テスト（epoll 版）
#   make asan         … AddressSanitizer + UBSan つきでビルド
#   make analyze      … 静的解析（gcc -fanalyzer）
#   make clean

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
SRC      = server.c
BIN      = server

# Windows(MinGW) では Winsock / mswsock、POSIX では pthread が要る
ifeq ($(OS),Windows_NT)
  LDLIBS_BASE = -lws2_32 -lmswsock
  BIN        := server.exe
else
  LDLIBS_BASE = -lpthread
endif

.PHONY: all epoll tls gzip all-variants test test-epoll asan analyze clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDLIBS_BASE)

epoll: $(SRC)
	$(CC) $(CFLAGS) -DUSE_EPOLL $(SRC) -o server_epoll $(LDLIBS_BASE)

tls: $(SRC)
	$(CC) $(CFLAGS) -DUSE_TLS $(SRC) -o server_tls $(LDLIBS_BASE) -lssl -lcrypto

gzip: $(SRC)
	$(CC) $(CFLAGS) -DUSE_GZIP $(SRC) -o server_gzip $(LDLIBS_BASE) -lz

all-variants: all epoll tls gzip

test: all
	bash tests/run_tests.sh

test-epoll: epoll
	USE_EPOLL=1 PORT=8972 bash tests/run_tests.sh

# 実行時にメモリエラー・未定義動作を検出する版
asan: $(SRC)
	$(CC) -Wall -Wextra -O1 -g -fsanitize=address,undefined \
	      -fno-omit-frame-pointer $(SRC) -o server_asan $(LDLIBS_BASE)

# コンパイラの静的解析器を通す（警告ゼロを目標にする）
analyze: $(SRC)
	$(CC) $(CFLAGS) -fanalyzer -c $(SRC) -o /dev/null

clean:
	rm -f server server.exe server_epoll server_tls server_gzip server_asan *.o
