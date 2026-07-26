# tiny-httpd

[![CI](https://github.com/Masah-111/tiny-httpd/actions/workflows/ci.yml/badge.svg)](https://github.com/Masah-111/tiny-httpd/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C](https://img.shields.io/badge/C-standard%20library%20only-555.svg)](server.c)

**フレームワークを使わず、C言語で TCP ソケットから自作した HTTP/1.1 静的ファイルサーバ。**
Apache や nginx が内部で何をしているのかを、標準ライブラリだけで手を動かして理解するために作りました。
v0.2 で**セキュリティ・堅牢性**、v0.3 で**同時接続・keep-alive・キャッシュ・Range・ゼロコピー**まで実装し、
実運用サーバの主要機能をひと通り自作しています。

*A from-scratch HTTP/1.1 static file server in C — no frameworks. Adds hardened path validation, request-size limits & timeouts, optional TLS (OpenSSL), plus concurrency, keep-alive, conditional GET (304), byte ranges (206), standard headers, and zero-copy sends.*

---

## これは何か

ブラウザに `http://localhost:8080/` と打つと HTML が返ってくる、あの当たり前の仕組みを、
ライブラリに隠さずに全部自分で書いたものです。単一ファイル（[`server.c`](server.c)）。

```
ブラウザ ──TCP接続──> tiny-httpd
        ──"GET / HTTP/1.1"──>
        <──"HTTP/1.1 200 OK" + ヘッダ + HTML──
```

## 機能一覧

### 基本
| 機能 | 説明 |
|---|---|
| TCP ソケット | `socket()` → `bind()` → `listen()` → `accept()` を直接呼ぶ |
| IPv6 デュアルスタック | `AF_INET6` + `IPV6_V6ONLY=0` で IPv4/IPv6 の両方を1つのソケットで受ける |
| HTTP 解析 | リクエストライン（メソッド / パス / バージョン）をパース |
| GET / HEAD / OPTIONS | HEAD は本文なし。OPTIONS は `Allow` を返す（204）|
| 静的ファイル配信 | `./www` 以下のファイルを返す |
| Content-Type 判定 | 拡張子から MIME タイプを決定 |
| URLデコード | `%20` などを復元 |
| ステータス応答 | 200 / 204 / 206 / 304 / 400 / 403 / 404 / 405 / 413 / 416 / 431 / 505 |
| 厳格なリクエスト検証 | 不正メソッド・非対応バージョン(505)・ヘッダ行数上限(431)・obs-fold や `:`欠落の行(400)を拒否 |
| Winsock / POSIX 両対応 | Windows でも Linux/macOS でも動く |

### セキュリティ・堅牢性（v0.2 で強化）
| 機能 | 説明 |
|---|---|
| **多層パス検査** | ①字句検査（`..`・バックスラッシュ・**コロン**・制御文字・`%00` ヌル注入・**Windows予約デバイス名**を拒否）→ ②`realpath`/`_fullpath` で正準化し `www` 内かを検証 → ③**開いたハンドルで最終検証**（POSIX: `O_NOFOLLOW`＋`fstat` で TOCTOU とシンボリックリンクを封じる／Windows: reparse point 拒否＋`GetFinalPathNameByHandle` で“開いた実体の正準パス”を再検証しジャンクション脱出を封じる）。三層の多層防御 |
| **リクエストサイズ制限** | ヘッダが上限（8 KB）を超えたら **431**、本文が上限（1 MB）を超えたら **413** を返して切断（巨大 `Content-Length` でワーカーを占有させない）|
| **リクエストスマグリング対策** | `Transfer-Encoding` は未対応なので **400 で拒否**。`Content-Length` と併存させた TE.CL / CL.TE スマグリングの温床を断つ |
| **64bit ファイルサイズ** | サイズ・オフセットを 64bit で扱い、**2 GB 超のファイル**も正しく配信（Windows の `long` は 32bit のため要注意な箇所）|
| **タイムアウト** | recv/send に 10 秒のタイムアウトを設定。だらだら送り続ける **Slowloris 型 DoS** を遮断 |
| **キュー・バックプレッシャ** | epoll 版のワークキューに上限を設け、洪水時は接続を落として（load shedding）メモリ枯渇を防ぐ |
| **同時接続数の上限** | 現在の接続数をアトミックに数え、上限（既定 10000・環境変数 `TINYHTTPD_MAX_CONN` で変更可）を超えたら即クローズ |
| **graceful shutdown** | `SIGINT`/`SIGTERM` で新規受付を止め、listen ソケットを閉じてから綺麗に終了。`SIGPIPE` は無視して送信中の切断で落ちない |
| **権限降格 (POSIX)** | root で起動した場合、bind 後に `setgroups`/`setgid`/`setuid` で非特権ユーザ（既定 `nobody`）へ降格 |
| **TLS / HTTPS** | OpenSSL による TLS 終端（コンパイル時オプション `-DUSE_TLS`。TLS1.2 以上のみ許可） |

### 高度な機能（v0.3〜0.4・すべてテスト済み）
| 機能 | 説明 |
|---|---|
| **同時接続** | 標準版は接続ごとにスレッド（thread-per-connection）。さらに Linux 向けに **epoll + スレッドプール版（C10K エディション）** を用意（下記）|
| **keep-alive** | HTTP/1.1 の既定どおり、1本の接続で複数リクエストを処理。`Connection` ヘッダを尊重、アイドルは 10 秒でクローズ |
| **ボディ対応** | `Content-Length` を読んでリクエスト本文を処理。`POST /echo` は受け取った本文をそのまま返す（本文を確実に読めている証明） |
| **キャッシュ (304)** | `ETag` と `Last-Modified` を付与。`If-None-Match`（厳密一致）と `If-Modified-Since`（**日付を実際にパースして大小比較**）に **304** で応答。`Cache-Control` も送出 |
| **Range (206)** | 単一 `Range` は **206**、複数 `Range` は **multipart/byteranges** で返す。`If-Range`（表現が変われば全体を返す）対応。満たせない範囲は **416** |
| **標準ヘッダ** | `Date` / `Server` / `Accept-Ranges` / `Connection` などを RFC 準拠の形式で付与 |
| **ゼロコピー送信** | 平文・全体配信時は `TransmitFile`(Windows) / `sendfile`(Linux) でカーネル内送信。TLS や Range では通常送信へ自動フォールバック |

#### 攻撃をどう弾くか（テスト済みの例）
| リクエスト | 結果 | 防いだもの |
|---|---|---|
| `GET /../server.c` | 403 | 素の親ディレクトリ参照 |
| `GET /..%2fserver.c` | 403 | エンコードで隠した `/` |
| `GET /%2e%2e/server.c` | 403 | エンコードで隠した `..` |
| `GET /..\server.c` | 403 | バックスラッシュによる区切り偽装 |
| `GET /x%00.html` | 400 | ヌルバイト注入 |
| `GET /index.html::$DATA` | 403 | 代替データストリーム(ADS) |
| `GET /c:/windows/x` | 403 | ドライブ指定 |
| `GET /nul` `/con` `/com1` | 403 | Windows予約デバイス名 |
| `GET /escape/server.c`（junction経由）| 403 | ジャンクションによる webroot 脱出 |
| `Transfer-Encoding: chunked` | 400 | リクエストスマグリング（TE.CL / CL.TE）|
| 1 MB 超の本文（`Content-Length`）| 413 | 巨大ボディによるワーカー占有 |
| 8 KB 超のヘッダ | 431 | ヘッダあふれ |
| 送信途中で沈黙 | 10 秒で切断 | Slowloris |

## ビルドと実行

### 平文 HTTP（依存ライブラリなし）

**Windows（MinGW-w64 / gcc）**
```bash
gcc server.c -o server.exe -lws2_32 -lmswsock
./server.exe            # http://localhost:8080/
./server.exe 3000       # ポート変更
```
> `-lmswsock` はゼロコピー送信（`TransmitFile`）のリンクに必要。

**Linux / macOS / WSL**
```bash
gcc server.c -o server -lpthread
./server
```
> `-lpthread` は同時接続（スレッド）のリンクに必要。

### HTTPS（TLS）を有効にする — OpenSSL が必要

> **注意:** TLS は OpenSSL ライブラリを使うため、環境に OpenSSL の開発パッケージが必要です。
> 標準の MinGW-w64 単体には入っていないので、**WSL / Linux か MSYS2 での有効化を推奨**します。

**1) OpenSSL を用意する**
- Linux / WSL: `sudo apt install libssl-dev openssl`
- MSYS2: `pacman -S mingw-w64-x86_64-openssl`

**2) TLS 付きでビルド**
```bash
# Linux / WSL / macOS
gcc server.c -o server -DUSE_TLS -lssl -lcrypto
# Windows(MSYS2)
gcc server.c -o server.exe -DUSE_TLS -lssl -lcrypto -lws2_32
```

**3) 自己署名証明書を作る（開発用）**
```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=localhost"
```

**4) HTTPS で起動**
```bash
./server 8443 cert.pem key.pem      # https://localhost:8443/
```
> 自己署名証明書なのでブラウザは警告を出します（開発用途では想定どおり）。本番では
> Let's Encrypt などの正式な証明書を使います。
>
> ✅ **検証済み**: WSL(OpenSSL 3.0) 上で `curl -k` が **TLS 1.3** でハンドシェイクし、
> GET/POST(/echo)/Range(206)/条件付きGET(304) がすべて HTTPS 越しに動作することを確認。

## C10K エディション（epoll + スレッドプール・Linux 専用）

thread-per-connection は「接続数ぶんのスレッド」が必要で、1万接続だとメモリ・スケジューリングが破綻する
（これが有名な **C10K 問題**）。そこで Linux 向けに、`epoll` をリアクターにした版を用意した。

- **1つの `epoll` で listen ソケットと全クライアントを監視**。待機中の接続は epoll に預けるだけで
  スレッドを消費しない。
- クライアントは **`EPOLLONESHOT`** で登録し、「読み取り可能になった接続」だけを**ワークキュー**へ。
- **CPU コア数ぶんの固定ワーカースレッド**がキューから取り出し、1リクエスト処理して epoll に再武装。
- => 実際に I/O が来た接続だけがスレッドを使う。**待機接続が何万あってもスレッドは数個のまま**。

```bash
# Linux / WSL のみ（epoll は Linux 専用）
gcc server.c -o server_epoll -DUSE_EPOLL -lpthread
./server_epoll 8080
```

**実測（WSL2 / 12 コア）**: 500 本のアイドル keep-alive 接続を保持したまま新規リクエストは **9.9 ms** で応答。
そのときのサーバのスレッド数は **13**（= 12 ワーカー + epoll スレッド 1）。500 接続でもスレッドは 13 本で済む。

> ※このエディションは TLS 非対応（TLS はノンブロッキングなハンドシェイクが必要で、本エディションの
> スコープ外）。`-DUSE_EPOLL` と `-DUSE_TLS` の同時指定はビルド時にエラーにしている。

## 設計上の判断（面接で聞かれたら答えられるように）

- **パス検査をなぜ三段構えにしたか**: 字句チェック（`..`/コロン/予約名 拒否）だけだと、シンボリックリンクや
  OS ごとのパス解釈差、検査後の差し替え（TOCTOU）で抜ける余地が残る。そこで ①字句 → ②正準化して
  webroot 内か → ③**実際に開いたハンドルで最終検証**、と重ねた。特に③が重要で、「検査したパス」と
  「実際に読むファイル」を必ず同一実体に固定する（POSIX は `O_NOFOLLOW`＋`fstat`、Windows は
  `GetFinalPathNameByHandle` で開いた実体の正準パスを取り再検証）。これで **Windows のジャンクション経由の
  脱出**（`_fullpath` は字句解決なので見逃す）と **TOCTOU 競合**を実際に塞いだ。
- **タイムアウトを入れた理由**: 接続を確立したまま 1 バイトずつ極端に遅く送る Slowloris は、
  少ないリソースでサーバの接続枠を占有できる。recv タイムアウトで遅すぎる接続を切る。
- **TLS を自作しなかった理由**: 暗号は自作しないのが鉄則。実装ミスが即脆弱性になるため、
  枯れた OpenSSL に委ね、自分は「TLS 終端をどう組み込むか」の設計に集中した。
- **平文/TLS を `conn_t` で抽象化**: 読み書きを `conn_recv`/`conn_send_all` に集約し、
  平文と TLS を同じ処理系で扱えるようにした（分岐を最小化）。ゼロコピー送信もこの抽象の内側で
  「平文のときだけ」切り替えている。
- **同時接続に thread-per-connection を選んだ理由**: まず「複数接続を同時に捌く」直感的な形を
  Winsock/POSIX 両対応で実装するため。共有する可変状態を持たない設計（`g_webroot` 等は起動時確定の
  読み取り専用）なのでロック不要。数千接続規模では `epoll` 等のイベント駆動が必要になる（下記「今後」）。
- **keep-alive とボディ読み取りは表裏一体**: 1本の接続で次の要求を正しく切り出すには、
  前の要求の本文（`Content-Length` 分）を最後まで読み切る必要がある。だから静的サーバでも
  ボディの読み取りは必須だった。
- **epoll で `EPOLLONESHOT` を選んだ理由**: fd が一度発火したら再武装まで epoll が黙るので、
  「同じ接続を2つのワーカーが同時に触る」競合が起きない。ワーカーは1リクエスト処理して
  再武装するだけでよく、ロック設計が単純になる。
- **リクエスト処理を `handle_one_request` に切り出した理由**: thread-per-connection と
  epoll+pool の2方式で、HTTP の中身（解析・検査・応答）を1バイトも重複させないため。
  差し替わるのは「接続の捌き方」だけ。
- **IPv6 デュアルスタックにした理由**: `AF_INET6` の1ソケットで `IPV6_V6ONLY=0` にすると、
  IPv4 接続が IPv4-mapped（`::ffff:a.b.c.d`）として同じソケットに入る。Linux は既定で
  デュアルスタックだが **Windows は既定 v6only=1** なので、明示的に 0 を設定して両対応を保証している。
- **graceful shutdown で listen ソケットを閉じる理由**: `accept()` でブロック中でも、
  シグナルハンドラから listen ソケットを閉じれば `accept()` が即座にエラーで戻り、
  ループを安全に抜けられる（Windows でも同じ手が使える）。

## わかったこと / 学び

- HTTP は「TCP の上で決まった書式のテキストをやり取りしているだけ」だと体感できた。
- `recv()` は 1 回で全部読めるとは限らず、`\r\n\r\n` を検出するまでループが要る。
- 「入力は信用しない」— `..`、エンコード回避、ヌル注入、巨大ヘッダ、遅延送信…と、
  正常系より**異常系の設計**の方が難しく、そこが堅牢性の本質だと分かった。
- 暗号は「使う技術」であって「作る技術」ではない、という現場の判断基準を理解した。

## 今後の拡張（Future work）

- [x] ~~同時接続対応~~（v0.3: thread-per-connection で実装）
- [x] ~~HTTP keep-alive~~（v0.3 で実装）
- [x] ~~キャッシュ対応（ETag / Last-Modified / 条件付き GET）~~（v0.3 で実装）
- [x] ~~Range リクエスト~~（v0.3 で実装）
- [x] ~~`epoll` によるイベント駆動 + スレッドプール（C10K 対応）~~（v0.4 で実装・Linux）
- [ ] `kqueue`(BSD/macOS) / IOCP(Windows) 対応で C10K をクロスプラットフォーム化
- [ ] ノンブロッキング I/O による部分リクエストの状態機械化（Slowloris を 1 スレッドも使わず捌く）
- [ ] HTTP パイプライン対応
- [ ] gzip 圧縮（`Content-Encoding`）
- [ ] アクセスログのファイル出力・ログレベル

### 現状の既知の割り切り（正直に）
- epoll 版のワーカーは「読み取り可能」通知を受けてから**ブロッキングで**1リクエストを読む
  （`recv` タイムアウトで上限あり）。完全なノンブロッキング状態機械ではないので、極端に遅い
  1リクエストは1ワーカーを一時占有しうる。ただし**待機接続はスレッドを消費しない**ので
  C10K の本質（大量のアイドル接続）は解決できている。
- HTTP パイプライン（本文の後ろに次の要求を詰める）は未対応。
- `Transfer-Encoding: chunked` のリクエスト本文は未対応（安全のため 400 で拒否）。
- TLS はコンパイル時オプション（`-DUSE_TLS`）。WSL(OpenSSL 3.0) で **ビルド＆HTTPS を実機検証済み**（curl と **TLS 1.3** でハンドシェイクし、GET/POST/Range/条件付きGET が動作）。CI でもコンパイルを検証する。
- epoll 版は Linux 専用・TLS 非対応（`kqueue`/IOCP と非ブロッキング TLS は今後）。

## テスト / CI

23 項目の統合テスト（[`tests/run_tests.sh`](tests/run_tests.sh)）を用意している。サーバをビルド・起動し、
curl と raw ソケットで各レスポンス（200/204/206/304/400/403/404/405/413/416/431/505、multipart、
条件付きGET、If-Range 等）を検証し、1件でも失敗すれば非ゼロ終了する。

```bash
bash tests/run_tests.sh              # portable(thread-per-connection) 版
USE_EPOLL=1 bash tests/run_tests.sh  # epoll(C10K) 版
```

GitHub Actions（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）で、push / PR ごとに
**portable・epoll・TLS の 3 構成をビルド**し、portable と epoll でこの統合テストを実行する。
（TLS 構成は `libssl-dev` を入れてコンパイル可能かを検証する。）

## ライセンス
MIT
