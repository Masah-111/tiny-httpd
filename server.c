/*
 * tiny-httpd v0.3 : フレームワーク不使用・C言語で自作した HTTP/1.1 サーバ
 * ===========================================================================
 * v0.3 で追加した「本格機能」:
 *   (A) 同時接続対応   … 接続ごとにスレッドを起動（thread-per-connection）
 *   (B) keep-alive     … 1本の接続で複数リクエストを処理（HTTP/1.1 既定）
 *   (C) ボディ対応      … Content-Length を読み、POST /echo は本文をそのまま返す
 *   (D) キャッシュ      … ETag / Last-Modified と条件付きGET → 304 Not Modified
 *   (E) Range           … "Range: bytes=.." に 206 Partial Content で応答（動画等）
 *   (F) 標準ヘッダ       … Date / Server / Accept-Ranges / Connection など
 *   (G) ゼロコピー送信   … 平文・全体配信時のみ TransmitFile/sendfile（TLS時は通常送信）
 *
 * v0.2 からのセキュリティ(多層パス検査・サイズ制限・タイムアウト・TLS)も継続。
 * ビルド/実行/TLSは README.md 参照。
 *
 * 作者: SATO MASAHIRO   ライセンス: MIT
 */

/* ===== プラットフォーム差分の吸収 ===== */
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <mswsock.h>          /* TransmitFile（ゼロコピー）*/
  #include <process.h>          /* _beginthreadex（スレッド）*/
  #include <stdint.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "mswsock.lib")
  typedef SOCKET sock_t;
  #define CLOSESOCK closesocket
  #define BAD_SOCK  INVALID_SOCKET
  #define HDRNCMP   _strnicmp    /* HTTPヘッダ名は大文字小文字を区別しない */
  #define PATHNCMP  _strnicmp
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/time.h>
  #include <sys/stat.h>
  #include <strings.h>
  #include <unistd.h>
  #include <pthread.h>          /* スレッド */
  #include <fcntl.h>            /* open / O_NOFOLLOW（TOCTOU・シンボリックリンク対策）*/
  #include <errno.h>
  #include <pwd.h>              /* 権限降格（getpwnam）*/
  #include <grp.h>             /* setgroups / setgid */
  #ifdef __linux__
    #include <sys/sendfile.h>   /* sendfile（ゼロコピー）*/
  #endif
  typedef int sock_t;
  #define CLOSESOCK close
  #define BAD_SOCK  (-1)
  #define HDRNCMP   strncasecmp
  #define PATHNCMP  strncmp
#endif

#ifdef USE_TLS
  #include <openssl/ssl.h>
  #include <openssl/err.h>
#endif

/* gzip 圧縮（zlib がある環境でのみ有効化するコンパイル時オプション）*/
#ifdef USE_GZIP
  #include <zlib.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>            /* graceful shutdown（SIGINT / SIGTERM）*/
#include <stdatomic.h>         /* 同時接続数カウンタ（スレッド安全）*/

/* epoll + スレッドプール版（C10K エディション、Linux 専用のコンパイル時オプション）*/
#if defined(__linux__) && defined(USE_EPOLL)
  #include <sys/epoll.h>
#endif
#if defined(USE_EPOLL) && defined(USE_TLS)
  #error "USE_EPOLL and USE_TLS are not supported together (TLS needs a non-blocking handshake; out of scope)."
#endif
#if defined(USE_EPOLL) && !defined(__linux__)
  #error "USE_EPOLL requires Linux (epoll is Linux-only). Build the portable version without -DUSE_EPOLL."
#endif

#define DEFAULT_PORT           8080
#define WEB_ROOT               "www"
#define REQ_BUF_SIZE           8192      /* ヘッダ上限（超えたら 431）*/
#define IO_TIMEOUT_SEC         10        /* recv/send タイムアウト（Slowloris & idle keep-alive 対策）*/
#define MAX_REQUESTS_PER_CONN  100       /* 1接続で捌く最大リクエスト数（keep-alive 濫用対策）*/
#define ECHO_CAP               65536     /* POST /echo で返す本文の上限 */
#define MAX_BODY_SIZE          (1LL << 20) /* リクエスト本文の上限 1MB（超えたら 413）*/
#define MAX_QUEUE_DEPTH        8192       /* epoll: ワークキュー上限（洪水時の load shedding）*/
#define MAX_HEADERS            64         /* ヘッダ行数の上限（超えたら 431）*/
#define MAX_RANGES             16         /* 1リクエストで受け付ける Range の数の上限 */
#define GZIP_MAX_SIZE          (4LL << 20) /* gzip 対象にする最大ファイルサイズ 4MB */
#define CACHE_MAX_AGE          3600       /* Cache-Control / Expires の秒数 */
#define PATH_BUF               4096
#define SERVER_NAME            "tiny-httpd/0.4 (SATO MASAHIRO)"

/* 起動時に確定する読み取り専用グローバル（スレッド間で共有しても安全）*/
static char g_webroot[PATH_BUF];
static int  g_use_tls = 0;
#ifdef USE_TLS
static SSL_CTX *g_ctx = NULL;
#endif

/* graceful shutdown / 同時接続数の管理 */
static volatile sig_atomic_t g_stop = 0;     /* シグナルで 1 になり accept ループを抜ける */
static sock_t     g_listen = BAD_SOCK;        /* ハンドラから閉じて accept のブロックを解除する */
static atomic_int g_conns = 0;                /* 現在の同時接続数 */
static int        g_max_conns = 10000;        /* 同時接続の上限（環境変数 TINYHTTPD_MAX_CONN で変更可）*/

/* ファイル情報の型（stat の差分吸収）*/
#ifdef _WIN32
  typedef struct _stat64 stat_t;
  #define STAT_FN _stat64
#else
  typedef struct stat stat_t;
  #define STAT_FN stat
#endif

/* ===========================================================================
 * 接続の抽象化: 平文でも TLS でも同じ conn_recv/conn_send で扱う
 * ========================================================================= */
typedef struct {
    sock_t sock;
    char   ip[46];
    int    reqcount;      /* この接続で処理したリクエスト数（keep-alive 上限管理）*/
#ifdef USE_TLS
    SSL *ssl;
#endif
} conn_t;

static int conn_is_tls(conn_t *c) {
#ifdef USE_TLS
    return c->ssl != NULL;
#else
    (void)c; return 0;
#endif
}

static int net_init(void) {
#ifdef _WIN32
    WSADATA wsa; return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}
static void net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static void set_io_timeout(sock_t s, int seconds) {
#ifdef _WIN32
    DWORD ms = (DWORD)seconds * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
#else
    struct timeval tv; tv.tv_sec = seconds; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

static int conn_recv(conn_t *c, char *buf, int len) {
#ifdef USE_TLS
    if (c->ssl) return SSL_read(c->ssl, buf, len);
#endif
    return recv(c->sock, buf, len, 0);
}
static int conn_send_all(conn_t *c, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n;
#ifdef USE_TLS
        if (c->ssl) n = SSL_write(c->ssl, buf + sent, (int)(len - sent));
        else        n = send(c->sock, buf + sent, (int)(len - sent), 0);
#else
        n = send(c->sock, buf + sent, (int)(len - sent), 0);
#endif
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}
static void conn_close(conn_t *c) {
#ifdef USE_TLS
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
#endif
    CLOSESOCK(c->sock);
}

/* ---------------------------------------------------------------------------
 * 小道具: MIME判定 / HTTP日付 / ヘッダ取得 / URLデコード / パス検査
 * ------------------------------------------------------------------------- */
/* 拡張子 → MIME タイプの表。compressible=1 のものだけ gzip の対象にする
 * （画像・動画・zip などは既に圧縮済みなので、再圧縮しても CPU の無駄）。*/
typedef struct { const char *ext, *mime; int compressible; } mime_entry;
static const mime_entry MIME_TABLE[] = {
    /* テキスト系（圧縮が効く）*/
    { ".html", "text/html; charset=utf-8",             1 },
    { ".htm",  "text/html; charset=utf-8",             1 },
    { ".css",  "text/css; charset=utf-8",              1 },
    { ".js",   "text/javascript; charset=utf-8",       1 },
    { ".mjs",  "text/javascript; charset=utf-8",       1 },
    { ".json", "application/json; charset=utf-8",      1 },
    { ".map",  "application/json; charset=utf-8",      1 },
    { ".txt",  "text/plain; charset=utf-8",            1 },
    { ".md",   "text/markdown; charset=utf-8",         1 },
    { ".csv",  "text/csv; charset=utf-8",              1 },
    { ".xml",  "application/xml; charset=utf-8",       1 },
    { ".svg",  "image/svg+xml",                        1 },
    { ".wasm", "application/wasm",                     1 },
    /* 画像（多くは圧縮済み）*/
    { ".png",  "image/png",                            0 },
    { ".jpg",  "image/jpeg",                           0 },
    { ".jpeg", "image/jpeg",                           0 },
    { ".gif",  "image/gif",                            0 },
    { ".webp", "image/webp",                           0 },
    { ".avif", "image/avif",                           0 },
    { ".bmp",  "image/bmp",                            1 },
    { ".ico",  "image/x-icon",                         0 },
    /* フォント */
    { ".woff", "font/woff",                            0 },
    { ".woff2","font/woff2",                           0 },
    { ".ttf",  "font/ttf",                             1 },
    { ".otf",  "font/otf",                             1 },
    /* 音声・動画 */
    { ".mp4",  "video/mp4",                            0 },
    { ".webm", "video/webm",                           0 },
    { ".ogg",  "audio/ogg",                            0 },
    { ".mp3",  "audio/mpeg",                           0 },
    { ".wav",  "audio/wav",                            0 },
    /* その他 */
    { ".pdf",  "application/pdf",                      0 },
    { ".zip",  "application/zip",                      0 },
    { ".gz",   "application/gzip",                     0 },
};

static const mime_entry *mime_lookup(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return NULL;
    for (size_t i = 0; i < sizeof(MIME_TABLE) / sizeof(MIME_TABLE[0]); i++) {
        const char *e = MIME_TABLE[i].ext;
        if (HDRNCMP(dot, e, strlen(e) + 1) == 0) return &MIME_TABLE[i];
    }
    return NULL;
}
static const char *content_type_of(const char *path) {
    const mime_entry *m = mime_lookup(path);
    return m ? m->mime : "application/octet-stream";
}
static int is_compressible(const char *path) {
    const mime_entry *m = mime_lookup(path);
    return m ? m->compressible : 0;
}

/* RFC1123 形式の GMT 日付文字列（例: "Sun, 26 Jul 2026 10:00:00 GMT"）*/
static void http_date(time_t t, char *buf, size_t n) {
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    /* C ロケール既定で英語表記。HTTP は英語固定なのでこれで正しい。*/
    strftime(buf, n, "%a, %d %b %Y %H:%M:%S GMT", &tmv);
}

/* RFC1123 の HTTP 日付文字列を time_t に変換する（If-Modified-Since / If-Range 用）。
 * 例: "Sun, 26 Jul 2026 10:00:00 GMT" -> Unix 秒。失敗時は (time_t)-1。
 * MinGW に strptime が無いため手書きでパースする。 */
static time_t parse_http_date(const char *s) {
    static const char *MON = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *p = strchr(s, ',');      /* 曜日をスキップ */
    p = p ? p + 1 : s;
    while (*p == ' ') p++;
    int day, year, hh, mm, ss;
    char mname[4] = {0};
    if (sscanf(p, "%d %3s %d %d:%d:%d", &day, mname, &year, &hh, &mm, &ss) != 6)
        return (time_t)-1;
    const char *mp = strstr(MON, mname);
    if (!mp || (int)(mp - MON) % 3 != 0) return (time_t)-1;   /* 月名を厳密に */
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_mday = day;
    tmv.tm_mon  = (int)(mp - MON) / 3;
    tmv.tm_year = year - 1900;
    tmv.tm_hour = hh; tmv.tm_min = mm; tmv.tm_sec = ss;
#ifdef _WIN32
    return _mkgmtime(&tmv);   /* GMT として解釈（ローカルタイム変換を避ける）*/
#else
    return timegm(&tmv);
#endif
}

/* アクセスログ（Common Log Format 風）。1行を組み立てて1回の fwrite で出力するので、
 * stdio のストリームロックにより複数スレッドからでも行が混ざらない（スレッドセーフ）。 */
static void access_log(const char *ip, const char *method, const char *path,
                       const char *version, int status) {
    char ts[40];
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &now);
#else
    gmtime_r(&now, &tmv);
#endif
    strftime(ts, sizeof ts, "%d/%b/%Y:%H:%M:%S +0000", &tmv);
    char line[2400];
    int n = snprintf(line, sizeof line, "%s - - [%s] \"%s %s %s\" %d\n",
                     ip, ts, method, path, version, status);
    if (n > 0) { fwrite(line, 1, (size_t)n, stdout); fflush(stdout); }
}

/* graceful shutdown: SIGINT/SIGTERM で受付を止める。listen ソケットを閉じて
 * accept() のブロックを解除する（close はシグナルハンドラで安全に呼べる）。 */
static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_listen != BAD_SOCK) { CLOSESOCK(g_listen); g_listen = BAD_SOCK; }
}

/* 接続元アドレスを文字列化（IPv6 対応）。IPv4-mapped（::ffff:1.2.3.4）は
 * 素の IPv4 表記に直して読みやすくする。 */
static void format_peer(const struct sockaddr_in6 *sa, char *out, size_t n) {
    char tmp[INET6_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET6, &sa->sin6_addr, tmp, sizeof tmp);
    if (strncmp(tmp, "::ffff:", 7) == 0) snprintf(out, n, "%s", tmp + 7);
    else                                 snprintf(out, n, "%s", tmp);
}

/* 権限降格: root で起動された場合、bind 後に非特権ユーザへ降格する（POSIX のみ）。
 * 万一の脆弱性が root 権限で悪用されるのを防ぐ、Web サーバの定石。 */
#ifndef _WIN32
static void drop_privileges(void) {
    if (geteuid() != 0) return;                 /* root でなければ何もしない */
    const char *uname = getenv("TINYHTTPD_USER");
    if (!uname) uname = "nobody";
    struct passwd *pw = getpwnam(uname);
    if (!pw) { fprintf(stderr, "drop_privileges: user '%s' not found\n", uname); exit(1); }
    if (setgroups(0, NULL) != 0 ||              /* 補助グループを捨てる */
        setgid(pw->pw_gid) != 0 ||
        setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "drop_privileges: failed to drop to '%s'\n", uname); exit(1);
    }
    printf("dropped privileges to '%s' (uid=%d, gid=%d)\n",
           uname, (int)pw->pw_uid, (int)pw->pw_gid);
}
#endif

/* ヘッダブロックから name の値を取り出す（大文字小文字無視）。1=見つかった */
static int header_get(const char *hdrs, const char *name, char *out, size_t outsz) {
    size_t nlen = strlen(name);
    const char *p = hdrs;
    while (p && *p) {
        if (p[0] == '\r' && p[1] == '\n') break;        /* ヘッダ終端 */
        if (HDRNCMP(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t i = 0;
            while (v[i] && v[i] != '\r' && v[i] != '\n' && i < outsz - 1) { out[i] = v[i]; i++; }
            out[i] = '\0';
            return 1;
        }
        const char *nl = strstr(p, "\r\n");
        if (!nl) break;
        p = nl + 2;
    }
    return 0;
}

/* ヘッダブロックを厳格に検証する（不正リクエストを早期に弾く）。
 * 戻り値: 0=OK / 400=不正な行 / 431=ヘッダが多すぎ */
static int validate_headers(const char *hdrs) {
    const char *p = hdrs;
    int count = 0;
    while (p && *p) {
        if (p[0] == '\r' && p[1] == '\n') break;       /* ヘッダ終端 */
        if (++count > MAX_HEADERS) return 431;         /* ヘッダ行が多すぎる */
        if (*p == ' ' || *p == '\t') return 400;       /* 行頭空白 = obs-fold（廃止）を拒否 */
        const char *colon = NULL, *q = p;
        while (*q && *q != '\r' && *q != '\n') {
            if (*q == ':') { colon = q; break; }
            if ((unsigned char)*q <= 0x20) return 400;  /* フィールド名に制御文字/空白 */
            q++;
        }
        if (!colon) return 400;                        /* ':' の無いヘッダ行 */
        const char *nl = strstr(p, "\r\n");
        if (!nl) return 400;
        p = nl + 2;
    }
    return 0;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int url_decode(const char *src, char *dst, size_t dst_size) {
    size_t di = 0;
    for (size_t i = 0; src[i] && di + 1 < dst_size; i++) {
        if (src[i] == '%' && hex_val(src[i + 1]) >= 0 && hex_val(src[i + 2]) >= 0) {
            int byte = hex_val(src[i + 1]) * 16 + hex_val(src[i + 2]);
            if (byte == 0) return -1;              /* %00 ヌル注入拒否 */
            dst[di++] = (char)byte; i += 2;
        } else dst[di++] = src[i];
    }
    dst[di] = '\0';
    return 0;
}
static int canonicalize(const char *in, char *out, size_t out_size) {
#ifdef _WIN32
    return _fullpath(out, in, out_size) ? 0 : -1;
#else
    char tmp[PATH_BUF];
    if (!realpath(in, tmp)) return -1;
    if (strlen(tmp) >= out_size) return -1;
    strcpy(out, tmp); return 0;
#endif
}
static int within_webroot(const char *resolved) {
    size_t rlen = strlen(g_webroot);
    if (PATHNCMP(resolved, g_webroot, rlen) != 0) return 0;
    char sep = resolved[rlen];
    return (sep == '\0' || sep == '/' || sep == '\\');
}
static int path_looks_safe(const char *path) {
    if (path[0] != '/') return -1;
    if (strstr(path, "..")) return -1;
    for (size_t i = 0; path[i]; i++) {
        unsigned char ch = (unsigned char)path[i];
        if (ch < 0x20) return -1;              /* 制御文字 */
        if (ch == '\\') return -1;             /* バックスラッシュ（区切り偽装）*/
        if (ch == ':')  return -1;             /* コロン（Windowsのドライブ指定・代替データストリーム対策）*/
    }
    return 0;
}

/* Windows の予約デバイス名（CON/NUL/COM1 等）を拒否する。
 * これらは拡張子やフォルダに関係なくデバイスとして開かれてしまうため危険。 */
#ifdef _WIN32
static int is_reserved_win(const char *path) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    char name[16];
    size_t i = 0;
    while (base[i] && base[i] != '.' && i < sizeof(name) - 1) { name[i] = base[i]; i++; }
    name[i] = '\0';
    static const char *res[] = { "CON", "PRN", "AUX", "NUL" };
    for (size_t k = 0; k < 4; k++) if (_stricmp(name, res[k]) == 0) return 1;
    if ((_strnicmp(name, "COM", 3) == 0 || _strnicmp(name, "LPT", 3) == 0) &&
        name[3] >= '1' && name[3] <= '9' && name[4] == '\0') return 1;
    return 0;
}
#endif

/* ---------------------------------------------------------------------------
 * レスポンス送信ヘルパ
 * ------------------------------------------------------------------------- */
static const char *conn_hdr(int keep_alive) {
    return keep_alive ? "Connection: keep-alive\r\nKeep-Alive: timeout=10\r\n"
                      : "Connection: close\r\n";
}

/* 本文つきの単純応答（エラーページや /echo に使う）*/
static void send_simple(conn_t *c, int code, const char *status,
                        const char *ctype, const char *body, size_t blen,
                        int keep_alive, int head_only) {
    char date[64]; http_date(time(NULL), date, sizeof date);
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Date: %s\r\n"
        "Server: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "\r\n",
        code, status, date, SERVER_NAME, ctype, blen, conn_hdr(keep_alive));
    conn_send_all(c, header, (size_t)hlen);
    if (!head_only && body && blen) conn_send_all(c, body, blen);
}

static void send_error(conn_t *c, int code, const char *status, int keep_alive) {
    char body[256];
    int blen = snprintf(body, sizeof(body),
        "<!doctype html><meta charset=\"utf-8\"><title>%d %s</title>"
        "<body style=\"font-family:sans-serif;text-align:center;padding:60px\">"
        "<h1>%d %s</h1><hr><p>%s</p></body>",
        code, status, code, status, SERVER_NAME);
    send_simple(c, code, status, "text/html; charset=utf-8", body, (size_t)blen, keep_alive, 0);
}

/* ---------------------------------------------------------------------------
 * 開いたファイルの抽象。TOCTOU 対策の要:
 *   「サイズ・更新日時の取得」も「本文の読み出し」も、この“開いたハンドル”で行う。
 *   検査したパスと実際に読むファイルが必ず同一実体になり、検査後の差し替えを防ぐ。
 * ------------------------------------------------------------------------- */
typedef struct {
#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
    long long size;                 /* 2GB 超に対応するため 64bit（Windows の long は 32bit）*/
    time_t    mtime;
} openfile_t;

static long of_read(openfile_t *of, char *buf, long len) {
#ifdef _WIN32
    DWORD got = 0;
    if (!ReadFile(of->h, buf, (DWORD)len, &got, NULL)) return -1;
    return (long)got;
#else
    return (long)read(of->fd, buf, (size_t)len);
#endif
}
static void of_seek(openfile_t *of, long long off) {
#ifdef _WIN32
    LARGE_INTEGER li; li.QuadPart = off;            /* 64bit オフセット */
    SetFilePointerEx(of->h, li, NULL, FILE_BEGIN);
#else
    lseek(of->fd, (off_t)off, SEEK_SET);
#endif
}
static void of_close(openfile_t *of) {
#ifdef _WIN32
    CloseHandle(of->h);
#else
    close(of->fd);
#endif
}

/* ファイルを“安全に”開き、開いた実体に対して最終検証まで行う。
 *   POSIX  : O_NOFOLLOW で最終要素のシンボリックリンクを拒否し、fstat で情報取得（TOCTOU 回避）。
 *            通常ファイル以外（デバイス/FIFO 等）も拒否。
 *   Windows: reparse point（ジャンクション/シンボリックリンク）を拒否。さらに
 *            GetFinalPathNameByHandle で“開いたハンドルの正準パス”を取得し、
 *            webroot 内かを再検証（経路途中のジャンクションによる脱出も防ぐ）。
 * 戻り値: 0=成功 / 404=存在しない / 403=拒否（リンク・デバイス・webroot 外）
 */
static int secure_open(const char *path, openfile_t *of) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 404;
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) return 403;   /* ジャンクション/シンボリックリンク */
    if (attr & FILE_ATTRIBUTE_DIRECTORY)     return 404;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return 404;
    char finalp[PATH_BUF];
    DWORD n = GetFinalPathNameByHandleA(h, finalp, sizeof finalp, FILE_NAME_NORMALIZED);
    if (n == 0 || n >= sizeof finalp) { CloseHandle(h); return 403; }
    const char *fp = finalp;
    if (strncmp(fp, "\\\\?\\", 4) == 0) fp += 4;           /* \\?\ プレフィックス除去 */
    if (!within_webroot(fp)) { CloseHandle(h); return 403; }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return 404; }
    FILETIME ftw; GetFileTime(h, NULL, NULL, &ftw);
    ULONGLONG t = (((ULONGLONG)ftw.dwHighDateTime) << 32) | ftw.dwLowDateTime;
    of->mtime = (time_t)(t / 10000000ULL - 11644473600ULL);  /* FILETIME→Unix秒 */
    of->size  = (long long)sz.QuadPart;
    of->h     = h;
    return 0;
#else
    int fd = open(path, O_RDONLY | O_NOFOLLOW
#ifdef O_CLOEXEC
        | O_CLOEXEC
#endif
    );
    if (fd < 0) return (errno == ELOOP) ? 403 : 404;         /* ELOOP = 最終要素がリンク */
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 404; }
    if (S_ISDIR(st.st_mode))  { close(fd); return 404; }
    if (!S_ISREG(st.st_mode)) { close(fd); return 403; }     /* デバイス/FIFO 等を拒否 */
    of->fd    = fd;
    of->size  = (long long)st.st_size;
    of->mtime = st.st_mtime;
    return 0;
#endif
}

/* ゼロコピー送信（平文のみ）。start から len バイトを送る。
 * Range 応答でも使えるよう、オフセットと長さを取る。0=成功 / -1=フォールバックせよ */
static int send_file_zerocopy(conn_t *c, openfile_t *of, long long start, long long len) {
    if (conn_is_tls(c)) return -1;                 /* TLS はゼロコピー不可（暗号化が要るため）*/
    if (len <= 0) return 0;
#if defined(_WIN32)
    /* TransmitFile はファイルポインタの位置から送るので、先に seek しておく。
     * 1回で送れる上限があるため、分割して送る。 */
    of_seek(of, start);
    long long left = len;
    while (left > 0) {
        DWORD chunk = (left > 0x7FFFFFFF) ? 0x7FFFFFFF : (DWORD)left;
        if (!TransmitFile(c->sock, of->h, chunk, 0, NULL, NULL, 0)) return -1;
        left -= chunk;
    }
    return 0;
#elif defined(__linux__)
    off_t off = (off_t)start;                       /* sendfile はオフセットを直接扱える */
    long long left = len;
    while (left > 0) {
        ssize_t s = sendfile(c->sock, of->fd, &off, (size_t)left);
        if (s <= 0) return -1;
        left -= s;
    }
    return 0;
#else
    (void)of; (void)start; return -1;               /* 非対応 OS はフォールバック */
#endif
}

/* ---------------------------------------------------------------------------
 * gzip 圧縮（-DUSE_GZIP のときのみ）。ファイル全体を読み込んで gzip 形式に圧縮する。
 * zlib の compress() は zlib 形式なので、gzip ヘッダを付けるため deflateInit2 に
 * windowBits = 15 + 16 を渡す。
 * 戻り値: 0=成功（*out を呼び出し側が free する）/ -1=失敗（非圧縮で送るべき）
 * ------------------------------------------------------------------------- */
#ifdef USE_GZIP
static int gzip_file(openfile_t *of, unsigned char **out, long long *out_len) {
    *out = NULL; *out_len = 0;
    if (of->size <= 0 || of->size > GZIP_MAX_SIZE) return -1;

    unsigned char *raw = (unsigned char *)malloc((size_t)of->size);
    if (!raw) return -1;
    of_seek(of, 0);
    long long got = 0;
    while (got < of->size) {
        long n = of_read(of, (char *)raw + got, (long)(of->size - got));
        if (n <= 0) break;
        got += n;
    }
    if (got != of->size) { free(raw); return -1; }

    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) { free(raw); return -1; }

    uLong cap = deflateBound(&zs, (uLong)got);
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) { deflateEnd(&zs); free(raw); return -1; }

    zs.next_in = raw;   zs.avail_in  = (uInt)got;
    zs.next_out = buf;  zs.avail_out = (uInt)cap;
    int rc = deflate(&zs, Z_FINISH);
    long long produced = (long long)zs.total_out;
    deflateEnd(&zs);
    free(raw);

    if (rc != Z_STREAM_END) { free(buf); return -1; }
    *out = buf; *out_len = produced;
    return 0;
}
#endif

/* 通常のバッファ送信（Range スライスにも使う）。開いたハンドルから読む。 */
static int send_file_buffered(conn_t *c, openfile_t *of, long long start, long long length) {
    of_seek(of, start);
    char buf[4096];
    long long remain = length;
    while (remain > 0) {
        long want = remain < (long long)sizeof(buf) ? (long)remain : (long)sizeof(buf);
        long n = of_read(of, buf, want);
        if (n <= 0) break;
        if (conn_send_all(c, buf, (size_t)n) < 0) return -1;
        remain -= n;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * ファイル配信（キャッシュ304 / Range206 / ゼロコピー / 標準ヘッダを内包）
 * 戻り値: ステータスコード（ログ用）
 * ------------------------------------------------------------------------- */
/* Range をパースする。spec は "bytes=" の後ろ（カンマ区切り可）。
 * 戻り値: >0=満たせる範囲の数（out に格納）/ 0=構文は正しいが全て満たせない(→416)
 *         / -1=構文が壊れている(→Range を無視して 200) */
typedef struct { long long start, end; } range_t;
static int parse_ranges(const char *spec, long long size, range_t *out, int maxr) {
    int n = 0;
    const char *p = spec;
    while (*p) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        long long s, e;
        char *endp;
        if (*p == '-') {                                   /* suffix: -N（末尾 N バイト）*/
            long long len = strtoll(p + 1, &endp, 10);
            if (endp == p + 1 || len <= 0) return -1;
            s = size - len; if (s < 0) s = 0; e = size - 1;
            p = endp;
        } else {
            s = strtoll(p, &endp, 10);
            if (endp == p || *endp != '-') return -1;
            p = endp + 1;
            if (*p == '\0' || *p == ',') { e = size - 1; }
            else {
                e = strtoll(p, &endp, 10);
                if (endp == p) return -1;
                p = endp;
            }
        }
        while (*p == ' ') p++;
        if (*p == ',') p++;
        else if (*p != '\0') return -1;                    /* 余計な文字 = 構文エラー */
        if (s > e || s >= size) continue;                  /* この範囲は満たせない → 飛ばす */
        if (e >= size) e = size - 1;
        if (n < maxr) { out[n].start = s; out[n].end = e; n++; }
    }
    return n;
}

/* 複数 Range を multipart/byteranges で返す（206）。head_only ならヘッダのみ。 */
static int send_multirange(conn_t *c, openfile_t *of, range_t *r, int n,
                           const char *ctype, long long size, const char *etag,
                           const char *lastmod, const char *date, int keep_alive,
                           int head_only) {
    char boundary[48];
    snprintf(boundary, sizeof boundary, "%08lx%08llx",
             (unsigned long)time(NULL), (unsigned long long)of->size);

    char parthdr[MAX_RANGES][192];
    int  plen[MAX_RANGES];
    long long total = 0;
    for (int i = 0; i < n; i++) {
        plen[i] = snprintf(parthdr[i], sizeof parthdr[i],
            "\r\n--%s\r\nContent-Type: %s\r\nContent-Range: bytes %lld-%lld/%lld\r\n\r\n",
            boundary, ctype, r[i].start, r[i].end, size);
        total += plen[i] + (r[i].end - r[i].start + 1);
    }
    char closing[64];
    int clen = snprintf(closing, sizeof closing, "\r\n--%s--\r\n", boundary);
    total += clen;

    char header[512];
    int hlen = snprintf(header, sizeof header,
        "HTTP/1.1 206 Partial Content\r\n"
        "Date: %s\r\nServer: %s\r\n"
        "Content-Type: multipart/byteranges; boundary=%s\r\n"
        "Content-Length: %lld\r\nAccept-Ranges: bytes\r\n"
        "ETag: %s\r\nLast-Modified: %s\r\nCache-Control: max-age=3600\r\n%s\r\n",
        date, SERVER_NAME, boundary, total, etag, lastmod, conn_hdr(keep_alive));
    conn_send_all(c, header, (size_t)hlen);

    if (!head_only) {
        for (int i = 0; i < n; i++) {
            conn_send_all(c, parthdr[i], (size_t)plen[i]);
            long long seglen = r[i].end - r[i].start + 1;
            if (send_file_zerocopy(c, of, r[i].start, seglen) != 0)   /* 各パートもゼロコピー */
                send_file_buffered(c, of, r[i].start, seglen);
        }
        conn_send_all(c, closing, (size_t)clen);
    }
    return 206;
}

static int serve_file(conn_t *c, const char *fs_path, const char *hdrs,
                      int head_only, int keep_alive) {
    openfile_t of;
    int oc = secure_open(fs_path, &of);               /* 開くと同時に多層の最終検証 */
    if (oc == 404) { send_error(c, 404, "Not Found", keep_alive); return 404; }
    if (oc == 403) { send_error(c, 403, "Forbidden", keep_alive); return 403; }

    long long size = of.size;
    char lastmod[64]; http_date(of.mtime, lastmod, sizeof lastmod);
    char date[64];    http_date(time(NULL), date, sizeof date);

    /* --- gzip を使うかを先に決める（ETag が変わるため、条件付きGET より前）---
     * Range 要求時は圧縮しない（範囲は元の表現に対する指定なので混ぜると壊れる）。*/
    int want_gzip = 0;
    int compressible = is_compressible(fs_path);
    char aebuf[128];
    int client_accepts_gzip = (header_get(hdrs, "Accept-Encoding", aebuf, sizeof aebuf) &&
                               strstr(aebuf, "gzip") != NULL);
    int has_range = (header_get(hdrs, "Range", aebuf, sizeof aebuf) != 0);
#ifdef USE_GZIP
    want_gzip = (compressible && client_accepts_gzip && !has_range &&
                 size > 0 && size <= GZIP_MAX_SIZE);
#else
    (void)client_accepts_gzip; (void)has_range;   /* gzip 無効ビルドでは使わない */
#endif

    /* ETag は「表現」ごとに異なる必要がある → gzip 版は接尾辞を付ける */
    char etag[72];
    snprintf(etag, sizeof etag, "\"%llx-%llx%s\"",
             (unsigned long long)size, (unsigned long long)of.mtime,
             want_gzip ? "-gz" : "");

    /* --- (D) 条件付きGET → 304 Not Modified --- */
    int not_modified = 0;
    char cond[128];
    if (header_get(hdrs, "If-None-Match", cond, sizeof cond)) {
        if (strcmp(cond, etag) == 0) not_modified = 1;         /* ETag は厳密一致 */
    } else if (header_get(hdrs, "If-Modified-Since", cond, sizeof cond)) {
        time_t ims = parse_http_date(cond);                    /* 日付を実際にパースして比較 */
        if (ims != (time_t)-1 && of.mtime <= ims) not_modified = 1;
    }
    /* 圧縮しうる資源は Vary を必ず付ける（キャッシュが別表現を混同しないように）*/
    const char *vary = compressible ? "Vary: Accept-Encoding\r\n" : "";

    if (not_modified) {
        char header[512];
        int hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 304 Not Modified\r\n"
            "Date: %s\r\nServer: %s\r\nETag: %s\r\nLast-Modified: %s\r\n%s%s\r\n",
            date, SERVER_NAME, etag, lastmod, vary, conn_hdr(keep_alive));
        conn_send_all(c, header, (size_t)hlen);
        of_close(&of);
        return 304;
    }

    /* --- gzip 応答（圧縮できたときだけ。失敗したら通常経路へ落ちる）--- */
#ifdef USE_GZIP
    if (want_gzip) {
        unsigned char *gz = NULL; long long gzlen = 0;
        if (gzip_file(&of, &gz, &gzlen) == 0) {
            char expires[64]; http_date(time(NULL) + CACHE_MAX_AGE, expires, sizeof expires);
            char header[768];
            int hlen = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Date: %s\r\nServer: %s\r\nContent-Type: %s\r\n"
                "Content-Encoding: gzip\r\nContent-Length: %lld\r\n"
                "ETag: %s\r\nLast-Modified: %s\r\n"
                "Cache-Control: max-age=%d\r\nExpires: %s\r\n%s%s\r\n",
                date, SERVER_NAME, content_type_of(fs_path), gzlen,
                etag, lastmod, CACHE_MAX_AGE, expires, vary, conn_hdr(keep_alive));
            conn_send_all(c, header, (size_t)hlen);
            if (!head_only) conn_send_all(c, (const char *)gz, (size_t)gzlen);
            free(gz);
            of_close(&of);
            return 200;
        }
        /* 圧縮に失敗 → 非圧縮で送る。ETag も非 gzip 版に戻す */
        snprintf(etag, sizeof etag, "\"%llx-%llx\"",
                 (unsigned long long)size, (unsigned long long)of.mtime);
    }
#endif

    /* --- (E) Range（複数対応 / If-Range 対応）--- */
    range_t ranges[MAX_RANGES];
    int nranges = 0;
    char rng[256];
    if (size > 0 && header_get(hdrs, "Range", rng, sizeof rng) && HDRNCMP(rng, "bytes=", 6) == 0) {
        /* If-Range: 表現(ETag/更新日時)が変わっていたら Range を無視して全体を返す */
        int honor = 1;
        char ifr[128];
        if (header_get(hdrs, "If-Range", ifr, sizeof ifr)) {
            if (ifr[0] == '"') honor = (strcmp(ifr, etag) == 0);
            else { time_t t = parse_http_date(ifr); honor = (t != (time_t)-1 && of.mtime <= t); }
        }
        if (honor) {
            int r = parse_ranges(rng + 6, size, ranges, MAX_RANGES);
            if (r == 0) {                                      /* 構文OKだが全て満たせない → 416 */
                char header[256];
                int hlen = snprintf(header, sizeof(header),
                    "HTTP/1.1 416 Range Not Satisfiable\r\n"
                    "Date: %s\r\nServer: %s\r\nContent-Range: bytes */%lld\r\n"
                    "Content-Length: 0\r\n%s\r\n",
                    date, SERVER_NAME, size, conn_hdr(keep_alive));
                conn_send_all(c, header, (size_t)hlen);
                of_close(&of);
                return 416;
            }
            if (r > 0) nranges = r;                            /* r==-1(構文エラー)は Range を無視 */
        }
    }

    /* --- 複数 Range は multipart/byteranges で返す --- */
    if (nranges > 1) {
        int st = send_multirange(c, &of, ranges, nranges, content_type_of(fs_path),
                                 size, etag, lastmod, date, keep_alive, head_only);
        of_close(&of);
        return st;
    }

    /* --- 単一 Range or 全体 --- */
    int is_range = (nranges == 1);
    long long start = is_range ? ranges[0].start : 0;
    long long end   = is_range ? ranges[0].end   : size - 1;
    long long body_len = is_range ? (end - start + 1) : size;
    int  status   = is_range ? 206 : 200;

    char expires[64]; http_date(time(NULL) + CACHE_MAX_AGE, expires, sizeof expires);
    char header[900];
    int hlen;
    if (is_range) {
        hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 206 Partial Content\r\n"
            "Date: %s\r\nServer: %s\r\nContent-Type: %s\r\n"
            "Content-Length: %lld\r\nContent-Range: bytes %lld-%lld/%lld\r\n"
            "Accept-Ranges: bytes\r\nETag: %s\r\nLast-Modified: %s\r\n"
            "Cache-Control: max-age=%d\r\nExpires: %s\r\n%s%s\r\n",
            date, SERVER_NAME, content_type_of(fs_path),
            body_len, start, end, size, etag, lastmod,
            CACHE_MAX_AGE, expires, vary, conn_hdr(keep_alive));
    } else {
        hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\nServer: %s\r\nContent-Type: %s\r\n"
            "Content-Length: %lld\r\nAccept-Ranges: bytes\r\n"
            "ETag: %s\r\nLast-Modified: %s\r\n"
            "Cache-Control: max-age=%d\r\nExpires: %s\r\n%s%s\r\n",
            date, SERVER_NAME, content_type_of(fs_path),
            body_len, etag, lastmod, CACHE_MAX_AGE, expires, vary, conn_hdr(keep_alive));
    }
    conn_send_all(c, header, (size_t)hlen);

    /* --- 本文送信 --- */
    if (!head_only && body_len > 0) {
        /* (G) 平文なら Range でもゼロコピーを試す（失敗したら通常送信にフォールバック）*/
        if (send_file_zerocopy(c, &of, start, body_len) != 0)
            send_file_buffered(c, &of, start, body_len);
    }
    of_close(&of);
    return status;
}

/* ---------------------------------------------------------------------------
 * ボディを読み取る（keep-alive のフレーミングに必須）。
 * capture!=0 なら先頭 ECHO_CAP バイトまでを *out に確保して返す。
 * already/already_len = ヘッダ読み込み時に既にバッファへ来ていた本文の先頭部分。
 * ------------------------------------------------------------------------- */
static void read_body(conn_t *c, const char *already, size_t already_len,
                      long long content_length, int capture, char **out, size_t *out_len) {
    *out = NULL; *out_len = 0;
    if (content_length <= 0) return;
    size_t need = (size_t)content_length;

    char *buf = NULL;
    if (capture) { buf = malloc(ECHO_CAP + 1); }

    size_t got = 0;
    size_t take = already_len < need ? already_len : need;   /* まずバッファ内の残り */
    if (buf && take) { size_t cp = take < ECHO_CAP ? take : ECHO_CAP; memcpy(buf, already, cp); *out_len = cp; }
    got = take;

    char tmp[4096];
    while (got < need) {
        size_t want = (need - got) < sizeof(tmp) ? (need - got) : sizeof(tmp);
        int n = conn_recv(c, tmp, (int)want);
        if (n <= 0) break;
        if (buf && *out_len < ECHO_CAP) {
            size_t room = ECHO_CAP - *out_len;
            size_t cp = (size_t)n < room ? (size_t)n : room;
            memcpy(buf + *out_len, tmp, cp); *out_len += cp;
        }
        got += (size_t)n;
    }
    if (buf) { buf[*out_len] = '\0'; *out = buf; }
}

/* ---------------------------------------------------------------------------
 * 1本の接続を処理（(A)スレッド内で呼ばれ、(B)keep-alive で複数回ループ）
 * ------------------------------------------------------------------------- */
/* リクエストを1つ処理する。両方式（thread-per-conn / epoll+pool）が共有する中核。
 * 戻り値: 1=この接続を保持して次のリクエストを待つ / 0=接続を閉じる */
static int handle_one_request(conn_t *c) {
    /* --- ヘッダを \r\n\r\n まで読む（上限超で 431）--- */
    char req[REQ_BUF_SIZE];
    size_t total = 0; int complete = 0;
    while (total < sizeof(req) - 1) {
        int n = conn_recv(c, req + total, (int)(sizeof(req) - 1 - total));
        if (n <= 0) return 0;                          /* 切断 / idle タイムアウト → 閉じる */
        total += (size_t)n; req[total] = '\0';
        if (strstr(req, "\r\n\r\n")) { complete = 1; break; }
    }
    if (!complete) { send_error(c, 431, "Request Header Fields Too Large", 0); return 0; }

    /* --- リクエストライン --- */
    char method[16] = {0}, raw_path[2048] = {0}, version[16] = {0};
    if (sscanf(req, "%15s %2047s %15s", method, raw_path, version) != 3) {
        send_error(c, 400, "Bad Request", 0); return 0;
    }
    /* (5) HTTP バージョンは 1.0 / 1.1 のみ受け付ける */
    if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0) {
        send_error(c, 505, "HTTP Version Not Supported", 0); return 0;
    }
    /* (5) メソッドは大文字トークンのみ（不正な制御文字などを弾く）*/
    for (const char *m = method; *m; m++)
        if (*m < 'A' || *m > 'Z') { send_error(c, 400, "Bad Request", 0); return 0; }

    /* ヘッダブロックの先頭と、本文の先頭（バッファ内）を求める */
    char *line_end = strstr(req, "\r\n");
    char *hdrs = line_end ? line_end + 2 : req + total;
    char *hend = strstr(req, "\r\n\r\n");
    char *body_in_buf = hend ? hend + 4 : req + total;
    size_t body_buffered = (size_t)(req + total - body_in_buf);

    /* (5) ヘッダを厳格に検証（行数上限・obs-fold・不正な行を拒否）*/
    int vh = validate_headers(hdrs);
    if (vh) {
        send_error(c, vh, vh == 431 ? "Request Header Fields Too Large" : "Bad Request", 0);
        return 0;
    }

    /* --- (B) keep-alive 判定: HTTP/1.1 は既定 ON、Connection ヘッダで上書き --- */
    int keep_alive = (strcmp(version, "HTTP/1.1") == 0);
    char conval[32];
    if (header_get(hdrs, "Connection", conval, sizeof conval)) {
        if (HDRNCMP(conval, "close", 5) == 0)      keep_alive = 0;
        else if (HDRNCMP(conval, "keep-alive", 10) == 0) keep_alive = 1;
    }

    /* --- リクエストスマグリング対策: Transfer-Encoding は未対応なので拒否 ---
     * chunked を誤って処理したり、Content-Length と併存させると
     * リクエストスマグリングの温床になる。安全側に倒して 400 で接続を閉じる。 */
    char tebuf[64];
    if (header_get(hdrs, "Transfer-Encoding", tebuf, sizeof tebuf)) {
        send_error(c, 400, "Bad Request", 0);
        return 0;
    }

    /* --- (C) Content-Length を見て本文を読む（フレーミング維持に必須）--- */
    long long clen = -1;
    char clbuf[32];
    if (header_get(hdrs, "Content-Length", clbuf, sizeof clbuf)) clen = atoll(clbuf);

    /* 本文サイズの上限（巨大 Content-Length でワーカーを占有させない）→ 413 */
    if (clen > MAX_BODY_SIZE) {
        send_error(c, 413, "Payload Too Large", 0);   /* フレーミング不明なので閉じる */
        return 0;
    }

    int is_get     = (strcmp(method, "GET") == 0);
    int is_head    = (strcmp(method, "HEAD") == 0);
    int is_post    = (strcmp(method, "POST") == 0);
    int is_options = (strcmp(method, "OPTIONS") == 0);

    char *qs = strchr(raw_path, '?');
    if (qs) *qs = '\0';
    char path[2048];
    int decode_ok = (url_decode(raw_path, path, sizeof path) == 0);

    int want_echo = (is_post && decode_ok && strcmp(path, "/echo") == 0);
    char  *body = NULL; size_t body_len = 0;
    read_body(c, body_in_buf, body_buffered, clen, want_echo, &body, &body_len);

    int status = 0;

    if (!decode_ok) {
        send_error(c, 400, "Bad Request", keep_alive); status = 400;
    } else if (is_get || is_head) {
        int unsafe = (path_looks_safe(path) != 0);
#ifdef _WIN32
        if (!unsafe && is_reserved_win(path)) unsafe = 1;   /* CON/NUL/COM1 等を拒否 */
#endif
        if (unsafe) {
            send_error(c, 403, "Forbidden", keep_alive); status = 403;
        } else {
            if (!strcmp(path, "/")) strcpy(path, "/index.html");
            char fs_path[PATH_BUF];
            snprintf(fs_path, sizeof fs_path, "%s%s", WEB_ROOT, path);
            char resolved[PATH_BUF];
            if (canonicalize(fs_path, resolved, sizeof resolved) != 0) {
                send_error(c, 404, "Not Found", keep_alive); status = 404;
            } else if (!within_webroot(resolved)) {
                send_error(c, 403, "Forbidden", keep_alive); status = 403;
            } else {
                status = serve_file(c, resolved, hdrs, is_head, keep_alive);
            }
        }
    } else if (want_echo) {
        send_simple(c, 200, "OK", "text/plain; charset=utf-8",
                    body ? body : "", body_len, keep_alive, 0);
        status = 200;
    } else if (is_options) {
        /* (8) OPTIONS: サーバが受け付けるメソッドを Allow で返す（204 No Content）*/
        char d[64]; http_date(time(NULL), d, sizeof d);
        char h[256];
        int hl = snprintf(h, sizeof h,
            "HTTP/1.1 204 No Content\r\nDate: %s\r\nServer: %s\r\n"
            "Allow: GET, HEAD, OPTIONS, POST\r\nContent-Length: 0\r\n%s\r\n",
            d, SERVER_NAME, conn_hdr(keep_alive));
        conn_send_all(c, h, (size_t)hl); status = 204;
    } else {
        /* (8) 405 には Allow ヘッダを付ける（RFC 準拠）*/
        char d[64]; http_date(time(NULL), d, sizeof d);
        char b405[128];
        int bl = snprintf(b405, sizeof b405,
            "<!doctype html><meta charset=\"utf-8\"><title>405</title><h1>405 Method Not Allowed</h1>");
        char h[384];
        int hl = snprintf(h, sizeof h,
            "HTTP/1.1 405 Method Not Allowed\r\nDate: %s\r\nServer: %s\r\n"
            "Allow: GET, HEAD, OPTIONS, POST\r\nContent-Type: text/html; charset=utf-8\r\n"
            "Content-Length: %d\r\n%s\r\n",
            d, SERVER_NAME, bl, conn_hdr(keep_alive));
        conn_send_all(c, h, (size_t)hl);
        conn_send_all(c, b405, (size_t)bl);
        status = 405;
    }

    if (body) free(body);

    access_log(c->ip, method, raw_path, version, status);

    c->reqcount++;
    return (keep_alive && c->reqcount < MAX_REQUESTS_PER_CONN) ? 1 : 0;
}

/* thread-per-connection 方式: 1接続を専有スレッドで keep-alive ループ処理
 * （epoll エディションでは pool_worker が代わりを務めるので不要）*/
#if !defined(USE_EPOLL)
static void handle_connection(conn_t *c) {
    while (handle_one_request(c)) { }
}
#endif

/* ===========================================================================
 * TLS セットアップ
 * ========================================================================= */
#ifdef USE_TLS
static SSL_CTX *tls_setup(const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ||
        !SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stderr); SSL_CTX_free(ctx); return NULL;
    }
    return ctx;
}
#endif

/* ===========================================================================
 * (A) 接続ごとのワーカースレッド（thread-per-connection 方式）
 * ========================================================================= */
#if !defined(USE_EPOLL)
#ifdef _WIN32
static unsigned __stdcall worker(void *arg)
#else
static void *worker(void *arg)
#endif
{
    conn_t *c = (conn_t *)arg;
#ifdef USE_TLS
    if (g_use_tls) {
        c->ssl = SSL_new(g_ctx);
        SSL_set_fd(c->ssl, (int)c->sock);
        if (SSL_accept(c->ssl) <= 0) {                 /* TLS ハンドシェイクもスレッド内で */
            ERR_print_errors_fp(stderr);
            conn_close(c); free(c); atomic_fetch_sub(&g_conns, 1); return 0;
        }
    }
#endif
    handle_connection(c);
    conn_close(c);
    free(c);
    atomic_fetch_sub(&g_conns, 1);                     /* 接続終了 → カウンタを戻す */
    return 0;
}
#endif /* !USE_EPOLL */

/* ===========================================================================
 * epoll + スレッドプール版（C10K エディション、-DUSE_EPOLL / Linux 専用）
 * ---------------------------------------------------------------------------
 * 設計:
 *   - epoll がリアクター。listen ソケットと全クライアントを1つの epoll で監視。
 *   - クライアントは EPOLLONESHOT で登録。読み取り可能になった接続だけを
 *     ワークキューへ積み、固定数のワーカースレッドが取り出して1リクエスト処理。
 *   - 処理後、keep-alive なら epoll に再登録(再武装)、そうでなければ閉じる。
 *   => 1万の待機接続は epoll に預けるだけでスレッドを消費しない。実際にI/Oが
 *      来た接続だけがワーカーを使う。これが thread-per-connection との決定的な差。
 * ========================================================================= */
#if defined(__linux__) && defined(USE_EPOLL)

#define MAX_EPOLL_EVENTS 1024
static int g_epfd = -1;

/* ---- ワークキュー（FIFO・mutex+condvar）---- */
typedef struct qnode { conn_t *conn; struct qnode *next; } qnode;
static qnode *g_qhead = NULL, *g_qtail = NULL;
static int    g_qlen = 0;
static pthread_mutex_t g_qmtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_qcond = PTHREAD_COND_INITIALIZER;

/* 戻り値: 0=積めた / -1=満杯 or メモリ不足（呼び出し側で接続を落とす）*/
static int queue_push(conn_t *c) {
    qnode *n = (qnode *)malloc(sizeof(qnode));
    if (!n) return -1;
    n->conn = c; n->next = NULL;
    pthread_mutex_lock(&g_qmtx);
    if (g_qlen >= MAX_QUEUE_DEPTH) {           /* バックプレッシャ: 洪水時は load shedding */
        pthread_mutex_unlock(&g_qmtx);
        free(n);
        return -1;
    }
    if (g_qtail) g_qtail->next = n; else g_qhead = n;
    g_qtail = n;
    g_qlen++;
    pthread_cond_signal(&g_qcond);
    pthread_mutex_unlock(&g_qmtx);
    return 0;
}
static conn_t *queue_pop(void) {
    pthread_mutex_lock(&g_qmtx);
    while (!g_qhead) pthread_cond_wait(&g_qcond, &g_qmtx);
    qnode *n = g_qhead;
    g_qhead = n->next;
    if (!g_qhead) g_qtail = NULL;
    g_qlen--;
    pthread_mutex_unlock(&g_qmtx);
    conn_t *c = n->conn; free(n);
    return c;
}

/* epoll からクライアントを取り除いて破棄し、同時接続数を1減らす */
static void epoll_drop(conn_t *c) {
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->sock, NULL);
    conn_close(c);
    free(c);
    atomic_fetch_sub(&g_conns, 1);
}

/* ---- プールのワーカー: キューから取り出して1リクエスト処理し、再武装 or 閉じる ---- */
static void *pool_worker(void *arg) {
    (void)arg;
    for (;;) {
        conn_t *c = queue_pop();
        int keep = handle_one_request(c);
        if (keep) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLONESHOT;
            ev.data.ptr = c;
            if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->sock, &ev) != 0)
                epoll_drop(c);                   /* 再武装できなければ閉じる */
        } else {
            epoll_drop(c);
        }
    }
    return NULL;
}

static void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* ---- epoll イベントループ本体（accept 専用スレッド兼リアクター）---- */
static void run_epoll(sock_t listen_sock) {
    set_nonblocking(listen_sock);              /* accept をノンブロッキングでまとめて捌く */
    g_epfd = epoll_create1(0);
    if (g_epfd < 0) { perror("epoll_create1"); return; }

    struct epoll_event lev;
    lev.events = EPOLLIN;                        /* listen はレベルトリガ・常時監視 */
    lev.data.ptr = NULL;                        /* NULL = listen ソケットの目印 */
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, listen_sock, &lev);

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    int nthreads = (ncpu < 4) ? 4 : (int)ncpu;  /* コア数ぶんのワーカー（最低4）*/
    for (int i = 0; i < nthreads; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, pool_worker, NULL) == 0) pthread_detach(t);
    }
    printf("concurrency: epoll + thread pool (%d workers)\n\n", nthreads);

    struct epoll_event evs[MAX_EPOLL_EVENTS];
    while (!g_stop) {
        int n = epoll_wait(g_epfd, evs, MAX_EPOLL_EVENTS, -1);
        if (n < 0) { if (errno == EINTR) continue; break; }  /* シグナルで抜ける */
        for (int i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {
                /* listen 可読: たまった接続をすべて accept して epoll に登録 */
                for (;;) {
                    struct sockaddr_in6 cli; socklen_t cl = sizeof(cli);
                    int client = accept(listen_sock, (struct sockaddr *)&cli, &cl);
                    if (client < 0) break;               /* EAGAIN で全部捌き終わり */
                    /* 同時接続数の上限（超過分は即クローズ = load shedding）*/
                    if (atomic_load(&g_conns) >= g_max_conns) { close(client); continue; }
                    set_io_timeout(client, IO_TIMEOUT_SEC);
                    conn_t *c = (conn_t *)malloc(sizeof(conn_t));
                    if (!c) { close(client); continue; }
                    c->sock = client; c->reqcount = 0;
#ifdef USE_TLS
                    c->ssl = NULL;
#endif
                    format_peer(&cli, c->ip, sizeof(c->ip));     /* IPv6 対応 */
                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLONESHOT;   /* 一度発火したら再武装まで黙る */
                    ev.data.ptr = c;
                    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, client, &ev) != 0) {
                        conn_close(c); free(c);
                    } else {
                        atomic_fetch_add(&g_conns, 1);   /* 登録できたら計上 */
                    }
                }
            } else {
                /* クライアント可読: ワーカーへ渡す（epoll スレッドは処理しない）*/
                conn_t *rc = (conn_t *)evs[i].data.ptr;
                if (queue_push(rc) != 0) epoll_drop(rc); /* 満杯: 接続を落として過負荷を捌く */
            }
        }
    }
}
#endif /* __linux__ && USE_EPOLL */

/* ===========================================================================
 * main
 * ========================================================================= */
int main(int argc, char **argv) {
    int port = (argc >= 2) ? atoi(argv[1]) : DEFAULT_PORT;
    const char *cert = (argc >= 4) ? argv[2] : NULL;
    const char *key  = (argc >= 4) ? argv[3] : NULL;

    if (net_init() != 0) { fprintf(stderr, "network init failed\n"); return 1; }

    if (canonicalize(WEB_ROOT, g_webroot, sizeof g_webroot) != 0) {
        fprintf(stderr, "web root '%s' not found. Run from the project directory.\n", WEB_ROOT);
        net_cleanup(); return 1;
    }

#ifdef USE_TLS
    if (cert && key) {
        g_ctx = tls_setup(cert, key);
        if (!g_ctx) { fprintf(stderr, "TLS setup failed\n"); net_cleanup(); return 1; }
        g_use_tls = 1;
    }
#else
    if (cert && key) {
        fprintf(stderr, "Built WITHOUT TLS. Rebuild: gcc server.c -o server -DUSE_TLS -lssl -lcrypto -lws2_32 -lmswsock\n");
        net_cleanup(); return 1;
    }
#endif

    /* --- IPv6 デュアルスタック: IPv6 ソケットで待ち受け、IPV6_V6ONLY=0 により
     *     IPv4（IPv4-mapped）接続も同じソケットで受ける。--- */
    sock_t listen_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sock == BAD_SOCK) { fprintf(stderr, "socket() failed\n"); return 1; }
    int yes = 1, no = 0;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&no, sizeof(no)); /* デュアルスタック */

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr   = in6addr_any;              /* :: = 全インタフェース */
    addr.sin6_port   = htons((unsigned short)port);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "bind() failed on port %d\n", port);
        CLOSESOCK(listen_sock); net_cleanup(); return 1;
    }
    if (listen(listen_sock, 64) != 0) {
        fprintf(stderr, "listen() failed\n");
        CLOSESOCK(listen_sock); net_cleanup(); return 1;
    }
    g_listen = listen_sock;

    /* --- graceful shutdown 用のシグナル登録 --- */
#ifdef _WIN32
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#else
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;                   /* SA_RESTART 無し → accept が EINTR で戻る */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);                    /* 送信中の切断でプロセスを殺さない */
    drop_privileges();                           /* root 起動なら bind 後に非特権ユーザへ降格 */
#endif

    /* --- 同時接続の上限（環境変数 TINYHTTPD_MAX_CONN で変更可）--- */
    { const char *m = getenv("TINYHTTPD_MAX_CONN"); if (m) { int v = atoi(m); if (v > 0) g_max_conns = v; } }

    printf("tiny-httpd v0.4 listening on %s://[::]:%d/ (IPv4+IPv6)  (root: %s)\n",
           g_use_tls ? "https" : "http", port, g_webroot);
    printf("features: keep-alive / body / cache-304 / range-206 / zero-copy / max-conn=%d\n", g_max_conns);
    printf("SIGINT/SIGTERM to stop gracefully.\n");

#if defined(__linux__) && defined(USE_EPOLL)
    /* C10K エディション: epoll + スレッドプール */
    run_epoll(listen_sock);
#else
    /* 標準エディション: accept ごとに専有スレッドを起動（thread-per-connection）*/
    printf("concurrency: thread-per-connection\n\n");
    while (!g_stop) {
        struct sockaddr_in6 cli; socklen_t cli_len = sizeof(cli);
        sock_t client = accept(listen_sock, (struct sockaddr *)&cli, &cli_len);
        if (client == BAD_SOCK) { if (g_stop) break; continue; }

        /* 同時接続の上限（超過分は即クローズ）*/
        if (atomic_fetch_add(&g_conns, 1) >= g_max_conns) {
            atomic_fetch_sub(&g_conns, 1); CLOSESOCK(client); continue;
        }
        set_io_timeout(client, IO_TIMEOUT_SEC);

        conn_t *c = (conn_t *)malloc(sizeof(conn_t));
        if (!c) { CLOSESOCK(client); atomic_fetch_sub(&g_conns, 1); continue; }
        c->sock = client; c->reqcount = 0;
#ifdef USE_TLS
        c->ssl = NULL;
#endif
        format_peer(&cli, c->ip, sizeof(c->ip));     /* IPv6 対応 */

#ifdef _WIN32
        uintptr_t h = _beginthreadex(NULL, 0, worker, c, 0, NULL);
        if (h) CloseHandle((HANDLE)h); else { conn_close(c); free(c); atomic_fetch_sub(&g_conns, 1); }
#else
        pthread_t t;
        if (pthread_create(&t, NULL, worker, c) == 0) pthread_detach(t);
        else { conn_close(c); free(c); atomic_fetch_sub(&g_conns, 1); }
#endif
    }
#endif

    printf("\nshutting down gracefully (no longer accepting connections)...\n");
    if (g_listen != BAD_SOCK) CLOSESOCK(g_listen);
#ifdef USE_TLS
    if (g_ctx) SSL_CTX_free(g_ctx);
#endif
    net_cleanup();
    return 0;
}
