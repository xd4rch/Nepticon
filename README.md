# Nepticon

**Lightweight TLS-Encrypted Fleet Telemetry & Remote Node Orchestration TUI**

[![tests](https://github.com/xd4rch/Nepticon/actions/workflows/tests.yml/badge.svg)](https://github.com/xd4rch/Nepticon/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Nepticon is a Python fleet operator console for small and medium infrastructure:
a TLS-only server, a self-reconnecting node agent, live resource telemetry,
concurrent fleet-wide commands, integrity-checked file transfer, and a
tamper-evident audit trail — all inside a `prompt_toolkit` terminal UI that keeps
the original Nepticon v1.2 identity.

[English](#english) · [Türkçe](#türkçe)

> [!WARNING]
> **Authorized use only.** Nepticon runs commands with the privileges of the
> account that starts the agent. Use it only on systems you are explicitly
> authorized to administer.

---

## English

### Why Nepticon

Most “remote shell” demos stop at a socket and a `recv()` call. Nepticon is
built around the operational questions a real fleet asks:

- *Which nodes are alive, and how slow is each one right now?*
- *What is the CPU/RAM/disk health of the whole fleet in one view?*
- *Can I run one maintenance command everywhere and see per-node results?*
- *Can I prove what I ran, on which node, and whether the file I copied is intact?*

It deliberately has **no web dependency, no database and no heavyweight agent
framework**. The server and agent are ordinary Python programs; only
`prompt_toolkit`, `tabulate` and `cryptography` (certificate tooling) are
required.

### Architecture

```text
                         operator terminal
                    ┌────────────────────────┐
                    │  FleetConsole (TUI)    │
                    │  prompt_toolkit        │
                    │  FLEET ⇄ NODE modes    │
                    └───────────┬────────────┘
                                │ in-process
                    ┌───────────▼────────────┐
                    │  FleetServer           │
                    │  TLS 1.2+ listener     │
                    │  node registry         │
                    │  audit.jsonl (SHA-256) │
                    └───────────┬────────────┘
                                │ TLS, 4-byte big-endian
                                │ length-prefixed UTF-8 JSON
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
   ┌──────▼──────┐       ┌──────▼──────┐       ┌──────▼──────┐
   │ Agent web-01│       │ Agent db-01 │       │ Agent edge  │
   │ telemetry   │       │ telemetry   │       │ telemetry   │
   │ exec / files│       │ exec / files│       │ exec / files│
   └─────────────┘       └─────────────┘       └─────────────┘
        ▲ outbound TLS only; agents never listen on an inbound port
```

**Components**

| Path | Role |
|---|---|
| `main.py` | TLS fleet server, node registry, fan-out operations, interactive console |
| `client.py` | Node agent: HELLO handshake, request execution, telemetry, file transfer, reconnect |
| `assets.py` | Original Nepticon v1.2 banner and visual identity |
| `nepticon/protocol.py` | Length-prefixed JSON framing, HMAC handshake, chunk/crypto helpers |
| `nepticon/telemetry.py` | Dependency-free CPU/RAM/disk/uptime/network/process collection |
| `nepticon/audit.py` | Thread-safe JSONL audit log with a SHA-256 hash chain |
| `nepticon/certs.py` | Local CA + server certificate generator (`--generate-certs`) |
| `nepticon/config.py` | CLI / environment / `config.json` configuration precedence |
| `nepticon/ui.py` | Colour, spinner, progress bar and table helpers |
| `tests/test_nepticon.py` | Loopback TLS integration tests (14 tests) |
| `.github/workflows/tests.yml` | Windows + Ubuntu CI matrix (Python 3.10/3.12/3.13) |
| `SECURITY.md` | Private vulnerability disclosure policy |
| `LICENSE` | MIT license |

### What changed from v1

| v1 problem | v2 resolution |
|---|---|
| Remote output was passed through `.format()`, so any `{` or `}` crashed the server | Remote output is opaque data and is never formatted |
| `recv(40960)` assumed one packet per message and truncated large output | 4-byte big-endian length-prefixed UTF-8 JSON envelope on every message |
| `client.py:coloring()` accidentally returned the SSL context | The shared colour helper returns text; no SSL object leaks into console output |
| Reconnect reused a socket created outside the loop | A fresh socket is created inside each attempt, with exponential backoff and jitter |
| `inspect.stack()` guessed which menu called `read()` | Explicit `SessionMode.FLEET_CONSOLE` / `SessionMode.NODE_SHELL` state |
| Hard-coded IP, port and certificate password | `NEPTICON_*` environment variables, `config.json`, CLI flags, generated certs |
| `os._exit(0)` skipped cleanup | Graceful shutdown: GOODBYE frames, socket close, audit `server_stop` |
| `PIL.ImageGrab` screenshot command | Removed; replaced with `sysinfo`, `health`, `ps`, `env` |

> [!IMPORTANT]
> The wire protocol is **not** backward compatible with v1. Upgrade the server
> and every agent together. The old `server.crt`/`server.key` files in the
> repository root are no longer loaded by default; archive or delete them and
> use the generated `certs/` directory (or your PKI) instead.

### Security model

| Control | Implementation |
|---|---|
| Transport encryption | TLS 1.2 minimum (1.3 negotiated where available), secure defaults |
| Server identity | Agent verifies the server with a CA certificate (`--ca`, `NEPTICON_CA`/`NEPTICON_CERT`) and hostname/IP check |
| Agent identity | HMAC-SHA256 over a canonical string containing agent version, hostname, per-connection nonce and timestamp |
| Token handling | The shared token is **never sent over the wire**; only a 16-hex token fingerprint and the HMAC signature are sent |
| Replay protection | 5-minute clock-skew window plus a nonce cache; nonces are stored only after the signature verifies |
| Brute-force resistance | Per-IP authentication-failure tracking (8 failures / 60 s) and bounded handshake concurrency |
| Message integrity | SHA-256 checksum for every upload/download; mismatch deletes the temporary file |
| Framing safety | 4-byte length prefix, 32 MiB frame cap, strict UTF-8 JSON validation |
| Audit integrity | Every audit record includes `prev` and `hash`; `audit verify` recomputes the chain |
| Secret handling | No embedded password, no hard-coded host; generated `config.json` is written with owner-only permissions where supported |
| Network exposure | Agents make outbound TLS connections only; no inbound agent listener |
| Privilege transparency | HELLO reports `admin`/`user`; the prompt and `list` table show it |

> [!NOTE]
> The audit chain detects accidental or opportunistic editing of the local file.
> It is not a substitute for shipping logs to an append-only remote system, because
> an attacker with root on the server can rewrite the whole file. The security
> model assumes the server host is trusted and the private key is protected.

### Platform support

| Platform | Status |
|---|---|
| Windows 10/11 | Primary development platform; the full test suite runs locally |
| Linux (Ubuntu/Debian, systemd or container) | Supported; uses `/proc`, `/sys`, POSIX signals and the standard library. The CI matrix runs the same suite on `ubuntu-latest` |
| macOS | Telemetry is best-effort; the TLS/fleet protocol is platform-neutral |

Linux notes: install with your distribution's Python 3.10+ interpreter, run the
agent under a dedicated service account, and allow outbound TCP to the server
port only. Both server and agent handle `SIGTERM` by closing sessions cleanly
and writing a final audit record. `systemd` unit sketches are intentionally
left to the operator; the programs are ordinary foreground processes.

### Requirements

- Python **3.10+** (tested with CPython 3.14 on Windows 11; Linux/macOS use `/proc` or standard APIs where available)
- `prompt_toolkit` 3.x
- `tabulate` 0.9+
- `cryptography` (certificate generation and fingerprinting; the TLS handshake itself uses the standard library)

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate
pip install -r requirements.txt
```

### Quick start (same host)

```bash
# Terminal 1 — fleet server. First run generates certs and a shared token.
python main.py

# Terminal 2 — node agent. It reads config.json for host/port/token/CA.
python client.py --name web-01
```

> [!TIP]
> The first server run prints the generated token once and writes it to
> `config.json`. Keep that file private. On subsequent runs the token is only
> shown masked.

```text
Nepticon@Fleet> list
Nepticon@Fleet> health-all
Nepticon@Fleet> select 1
Nepticon@Node[web-01]> health
Nepticon@Node[web-01]> ps 10
Nepticon@Node[web-01]> upload C:\builds\agent.zip /opt/nepticon/agent.zip
Nepticon@Node[web-01]> download /var/log/syslog
Nepticon@Node[web-01]> back
Nepticon@Fleet> audit verify
```

### Quick start (remote node)

1. Generate or obtain a CA/server certificate whose SAN covers the address
   agents will use:
   ```bash
   python main.py --generate-certs --san 10.20.30.40
   ```
2. Start the server with a stable token:
   ```bash
   python main.py --host 0.0.0.0 --port 1536 --token "$NEPTICON_TOKEN"
   ```
3. Copy **only** `certs/ca.crt` and the token to the node. On the node:
   ```bash
   python client.py --host 10.20.30.40 --port 1536 \
       --ca ca.crt --token "$NEPTICON_TOKEN" --name web-01
   ```
4. Permit outbound TCP 1536 on the server's firewall; no inbound port is
   needed on the node.

For production, replace the generated local CA with your organisation's PKI
certificate and protect `server.key` with OS permissions or a secrets manager.

### Configuration

Precedence, highest first:

1. command-line flags
2. `NEPTICON_*` environment variables
3. `config.json` (or `--config FILE`)
4. built-in defaults

| Variable | Meaning |
|---|---|
| `NEPTICON_HOST` | Server bind address / agent target host |
| `NEPTICON_PORT` | TLS port (default `1536`) |
| `NEPTICON_TOKEN` | Shared HMAC token |
| `NEPTICON_CERT` | Server certificate PEM; also used as trust anchor by an agent when `NEPTICON_CA` is absent |
| `NEPTICON_KEY` | Server private key PEM |
| `NEPTICON_CA` | CA certificate used by the agent |
| `NEPTICON_CONFIG` | Config file path |
| `NEPTICON_AUDIT_LOG` | Audit JSONL path (server) |
| `NEPTICON_DOWNLOADS` | Received-file directory |
| `NEPTICON_NAME` | Node display name |
| `NEPTICON_INSECURE` | `1` disables TLS verification (lab only) |
| `NEPTICON_HEARTBEAT` | Heartbeat interval in seconds |
| `NEPTICON_REQUEST_TIMEOUT` | Request timeout in seconds |
| `NEPTICON_MAX_NODES` | Maximum concurrent authenticated nodes |
| `NEPTICON_NO_COLOR` | Disable ANSI colour |
| `NEPTICON_NO_ANIMATIONS` | Disable spinners |
| `NEPTICON_VERBOSE` | Verbose logging |

`config.example.json` shows the file format. The server writes a generated token
to `config.json` (mode `0600` where the platform supports it) only when no token
was configured. CLI flags override the file for a single run.

Useful flags:

```text
--host --port --token --cert --key --ca --config
--audit-log --downloads --heartbeat --request-timeout --transfer-timeout
--max-nodes --generate-certs [DIR] --force-certs --san NAME
--no-color --no-animations --verbose --version
```

Agent-only: `--name`, `--insecure`.

### Command reference

#### Fleet console (`Nepticon@Fleet`)

| Command | Description |
|---|---|
| `list` / `nodes` | Live-ping every node and show ID, hostname, endpoint, OS, privilege, uptime, latency and status |
| `health-all` / `metrics-all` / `fleet-health` | Collect telemetry from all nodes concurrently and print one summary table |
| `broadcast <command>` | Run one shell command on every node concurrently, with per-node output and a summary table |
| `select <id\|hostname>` | Enter the interactive management session for one node |
| `audit [count]` | Show the most recent audit records (default 20, max 500) |
| `audit verify` | Recompute the SHA-256 audit chain |
| `status` | Show configuration, TLS fingerprint, node count, uptime and audit state |
| `help` | Command reference |
| `banner` / `clear` | Reprint the banner / clear the terminal |
| `quit` / `exit` | Graceful server shutdown |

#### Node shell (`Nepticon@Node[hostname]`)

| Command | Description |
|---|---|
| `health` / `metrics` | Live CPU, load, RAM, disk, uptime, Python, OS and network interfaces |
| `sysinfo` | Kernel, Python, user, privilege, PID, working directory, boot time |
| `ps [n]` | Top `n` processes by resident memory (default 20, max 100) |
| `env` | Environment variables with secret-looking names redacted, plus runtime/service context |
| `cd <path>` / `pwd` | Change/query the agent working directory |
| `upload <local> [remote]` | Server → node, 64 KiB chunks, progress, SHA-256 verified |
| `download <remote> [local]` | Node → server, 64 KiB chunks, progress, SHA-256 verified |
| `exec <command>` | Explicitly execute a shell command (otherwise any unrecognized input is executed) |
| `disconnect` | Drop the session; the agent reconnects automatically |
| `shutdown --force` | Terminate the agent process (requires `--force`) |
| `back` / `exit` / `quit` | Return to the fleet console |
| `help` / `banner` / `clear` | UI helpers |

> [!TIP]
> File transfer direction is always named from the **server's** point of view:
> `upload` pushes a server file to the node, `download` pulls a node file to the
> server. Downloads land in `--downloads` (default `./downloads`) with a unique
> name; uploads without an explicit remote path land in the agent's download
> directory.

### Wire protocol

Every message is a JSON object encoded as UTF-8 and prefixed with a 4-byte
big-endian length:

```text
┌──────────────────┬──────────────────────────────────────┐
│ uint32 length N  │ N bytes of UTF-8 JSON envelope       │
└──────────────────┴──────────────────────────────────────┘

{"v":1,"type":"REQUEST","id":"…","ts":1770000000.0,
 "data":{"op":"exec","args":{"command":"uptime"}}}
```

Message types: `HELLO`, `WELCOME`, `AUTH_FAIL`, `REQUEST`, `RESPONSE`, `PING`,
`PONG`, `FILE_BEGIN`, `FILE_CHUNK`, `FILE_END`, `FILE_ABORT`, `GOODBYE`.
File chunks carry base64 data, so file transfer remains inside the same JSON
envelope; the receiver enforces sequence numbers, declared size and SHA-256.

HELLO is signed over:

```text
nepticon-hello-v1\n<agent_version>\n<hostname>\n<nonce>\n<unix_timestamp>
```

with `HMAC-SHA256(shared_token, canonical_string)`. The server also verifies the
token fingerprint, timestamp skew and nonce freshness before accepting the node.

### Audit trail

Every connection, command, fleet operation, session selection and file transfer
is appended to `logs/audit.jsonl` by default:

```json
{"ts":"2026-11-02T18:31:04.120Z","event":"command","severity":"info",
 "actor":"fleet-console","node":"web-01","peer":"10.20.30.5:49152",
 "detail":{"command":"systemctl restart nginx","ok":true,
           "exit_code":0,"duration_ms":812.4,"stdout_bytes":0,
           "stderr_bytes":0},
 "prev":"…64 hex…","hash":"…64 hex…"}
```

> [!NOTE]
> Only metadata is stored, never command output. `audit verify` walks the file and
> reports the first line whose content or `prev` link does not match. Ship the file
> to an append-only collector for stronger guarantees.

### Usage scenarios

**1. Morning fleet triage**

```text
Nepticon@Fleet> health-all
Nepticon@Fleet> select db-01
Nepticon@Node[db-01]> health
Nepticon@Node[db-01]> ps 15
Nepticon@Node[db-01]> env
```

Correlate disk pressure, memory hogs and service context without opening five
SSH sessions.

**2. Maintenance window**

```text
Nepticon@Fleet> broadcast systemctl status nginx
Nepticon@Fleet> broadcast systemctl restart nginx
Nepticon@Fleet> health-all
```

Broadcast runs concurrently, reports each node's exit code and prints a
per-node output block. There is no dry-run engine: validate the command first on
one node with `select`.

**3. Incident artifact collection**

```text
Nepticon@Node[web-01]> download /var/log/nginx/error.log
Nepticon@Node[web-01]> download /etc/nginx/nginx.conf ./artifacts/nginx.conf
```

Both directions verify SHA-256 and print the short digest; the audit record keeps
the full digest and byte count.

**4. Controlled rollout**

```text
Nepticon@Node[web-01]> upload ./build/web-2.4.1.tar.gz /tmp/web-2.4.1.tar.gz
Nepticon@Fleet> broadcast tar -tzf /tmp/web-2.4.1.tar.gz > /dev/null && echo artifact-ok
```

The transfer is atomic (temporary file + `os.replace`) and checksum-verified
before the node reports success.

### Testing

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the same suite on `ubuntu-latest` and `windows-latest` for
Python 3.10, 3.12 and 3.13. The suite starts a real TLS server and a real agent
on `127.0.0.1` with a temporary local CA, then verifies:

- framing of a 300 KB / 600 KB payload containing braces over TCP and TLS;
- oversized-frame rejection;
- authenticated HELLO fields and rejection of a wrong token;
- remote command output containing JSON, `%s`, `{0}` and literal braces;
- concurrent `broadcast` and `fleet-health`;
- CPU/RAM/disk/uptime/network telemetry types and ranges;
- `sysinfo`, `ps` and secret redaction in `env`;
- 64 KiB-chunk upload/download with SHA-256 equality and audit records;
- audit hash-chain verification and tamper detection;
- the `coloring()` regression that used to return an `SSLContext`;
- reconnection after a server restart (fresh socket + backoff path).

### Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` | Agent is using the wrong CA, or the server certificate SAN does not cover the address. Regenerate with `--san <host-or-ip>` and distribute `ca.crt`. |
| Agent exits with `authentication rejected` | Token mismatch between server and agent. Use the same `config.json`/`NEPTICON_TOKEN`; the agent deliberately does not loop forever on bad credentials. |
| `Address already in use` | Another process owns the port. Change `--port` or stop the other listener. |
| `download` times out on a large file | Raise `--transfer-timeout`; check disk space on both ends. |
| Command finishes remotely but the console times out | The server request timeout is shorter than the command. Raise `--request-timeout` (default 30 s) and/or pass a command timeout. |
| Garbled box characters on Windows | Use Windows Terminal and a UTF-8 code page; Nepticon replaces unsupported characters instead of crashing. |
| No connection from a remote node | Allow outbound TCP to the server port; the node needs no inbound listener. |
| `audit verify` reports a broken chain | The JSONL file was edited, reordered or partially copied. Restore from backup and investigate. |

### Limitations and operational notes

> [!CAUTION]
> Anyone holding the shared token can administer every connected node. There is
> no RBAC or approval workflow. Run the agent with a dedicated least-privilege
> account, keep the token and CA private, and never use `--insecure` outside an
> isolated lab.

- Nepticon is a **fleet console**, not a full configuration-management system. It
  has no RBAC, approval workflow or multi-operator session isolation; anyone who
  holds the shared token can administer every connected node.
- Commands are non-interactive (no PTY). Use `exec` for one-shot commands; use
  SSH for interactive shells.
- The agent runs with the privileges of its service account. Set the `admin`/
  `user` expectation deliberately and prefer a dedicated least-privilege account.
- Telemetry is sampled on request. It is not a time-series database.
- Windows uses `ctypes` Win32 APIs; Linux uses `/proc` and `/sys`; macOS support
  is best-effort. Container environments may expose limited host metrics.
- A local hash-chained audit log is tamper-*evident*, not tamper-*proof*. Export
  it to an append-only system if that guarantee is required.
- Generated certificates are for labs and internal tooling. Use your PKI in
  production, and never use `--insecure` outside an isolated test network.

### License and credits

Nepticon is open source under the [MIT License](LICENSE). Copyright (c) 2026
xd4rch. Nepticon v1.2 visual identity and the original “quartrinary” banner are
preserved from the original project.

### Security policy

Please report vulnerabilities privately through GitHub Security Advisories
rather than in a public issue. See [SECURITY.md](SECURITY.md).

---

## Türkçe

### Genel bakış

**Nepticon**, küçük ve orta ölçekli altyapılar için geliştirilmiş, tamamen TLS
üzerinden çalışan bir **filo telemetrisi ve uzaktan düğüm yönetim TUI aracıdır**.
Sunucu ve düğüm ajanı sıradan Python programlarıdır; ağır bir ajan çerçevesi,
veritabanı veya web bağımlılığı yoktur. Orijinal Nepticon v1.2 ASCII banner'ı,
komut geçmişi, otomatik tamamlama, alt bilgi çubuğu ve yükleme animasyonları
korunmuştur.

Temel yetenekler:

- TLS 1.2+ üzerinden HMAC-SHA256 kimlik doğrulamalı ajan el sıkışması
- CPU, RAM, disk, çalışma süresi, Python/OS ve ağ arayüzü telemetrisi
- `list`, `health-all`, `broadcast` ve `select` ile filo geneli yönetim
- 64 KiB parçalı, ilerleme göstergeli, SHA-256 doğrulamalı dosya aktarımı
- SHA-256 zincirli, değiştirilebilirliği tespit eden `audit.jsonl` denetim kaydı
- Üstel geri çekilme ve jitter ile otomatik yeniden bağlanma
- `prompt_toolkit` tabanlı, mod bilinci açık (`Nepticon@Fleet` / `Nepticon@Node[...]`) konsol

> [!WARNING]
> **Yalnızca yetkili kullanım.** Nepticon, ajanı başlatan hesabın yetkileriyle
> komut çalıştırır. Yalnızca yönetmeye açıkça yetkili olduğunuz sistemlerde
> kullanın.

### Mimari

```text
                    operatör terminali
              ┌──────────────────────────┐
              │  FleetConsole (TUI)      │
              │  prompt_toolkit          │
              │  FLEET ⇄ NODE modları    │
              └────────────┬─────────────┘
                           │ süreç içi
              ┌────────────▼─────────────┐
              │  FleetServer             │
              │  TLS 1.2+ dinleyici      │
              │  düğüm kayıt defteri     │
              │  audit.jsonl (SHA-256)   │
              └────────────┬─────────────┘
                           │ TLS + 4 bayt big-endian
                           │ uzunluk önekli UTF-8 JSON
        ┌──────────────────┼──────────────────┐
        │                  │                  │
  ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
  │ web-01    │      │ db-01     │      │ edge-01   │
  │ telemetri │      │ telemetri │      │ telemetri │
  │ komut/dosya│     │ komut/dosya│     │ komut/dosya│
  └───────────┘      └───────────┘      └───────────┘
       ▲ ajanlar yalnızca dışarı bağlanır; gelen bağlantı dinlemez
```

Bileşenler:

| Dosya | Görev |
|---|---|
| `main.py` | TLS filo sunucusu, düğüm kaydı, toplu işlemler, etkileşimli konsol |
| `client.py` | Düğüm ajanı: HELLO, komut yürütme, telemetri, dosya aktarımı, yeniden bağlanma |
| `assets.py` | Orijinal Nepticon v1.2 banner'ı |
| `nepticon/protocol.py` | Çerçeveleme, HMAC el sıkışması, parça/kripto yardımcıları |
| `nepticon/telemetry.py` | `ctypes` Win32 / `/proc` / `shutil` ile bağımlılıksız telemetri |
| `nepticon/audit.py` | SHA-256 zincirli, iş parçacığı güvenli JSONL denetim kaydı |
| `nepticon/certs.py` | Yerel CA ve sunucu sertifikası üretimi |
| `nepticon/config.py` | CLI / ortam değişkeni / `config.json` öncelik sırası |
| `nepticon/ui.py` | Renk, spinner, ilerleme çubuğu ve tablo yardımcıları |
| `tests/test_nepticon.py` | Loopback TLS entegrasyon testleri (14 test) |
| `.github/workflows/tests.yml` | Windows + Ubuntu CI matrisi (Python 3.10/3.12/3.13) |
| `SECURITY.md` | Özel güvenlik açığı bildirim politikası |
| `LICENSE` | MIT lisansı |

### v1'den gelen düzeltmeler

| v1 hatası | v2 çözümü |
|---|---|
| Uzak çıktıya `.format()` uygulanması; `{`/`}` içeren JSON veya kodda çökme | Uzak çıktı opak veridir, asla biçimlendirilmez |
| `recv(40960)` ile mesaj sınırı varsayımı ve büyük çıktıda bozulma | Her mesajda 4 bayt big-endian uzunluk önekli UTF-8 JSON zarfı |
| `coloring()` fonksiyonunun `SSLContext` döndürmesi | Paylaşılan renk yardımcısı metin döndürür |
| Yeniden bağlanmada döngü dışında oluşturulan soketin kullanılması | Her denemede `try` içinde yeni soket + üstel geri çekilme + jitter |
| `inspect.stack()` ile menü tahmini | Açık `SessionMode.FLEET_CONSOLE` / `SessionMode.NODE_SHELL` durumu |
| Gömülü IP, parola ve sertifika | `NEPTICON_*`, `config.json`, CLI ve `--generate-certs` |
| `os._exit(0)` ile temizliksiz çıkış | GOODBYE, soket kapatma ve `server_stop` denetim kaydı |
| `PIL.ImageGrab` ekran görüntüsü | Kaldırıldı; `sysinfo`, `health`, `ps`, `env` eklendi |

> [!IMPORTANT]
> Tel protokolü v1 ile **uyumlu değildir**. Sunucu ve tüm ajanlar birlikte
> güncellenmelidir. Depo kökündeki eski `server.crt`/`server.key` dosyaları
> artık varsayılan olarak yüklenmez; bunları arşivleyin veya silin ve üretilen
> `certs/` dizinini (ya da kendi PKI'nızı) kullanın.

### Güvenlik modeli

| Kontrol | Uygulama |
|---|---|
| Taşıma şifrelemesi | En az TLS 1.2; mümkünse TLS 1.3 |
| Sunucu kimliği | Ajan, CA sertifikası ve hostname/IP doğrulaması yapar |
| Ajan kimliği | Ajan sürümü, hostname, bağlantıya özel nonce ve zaman damgası üzerinden HMAC-SHA256 |
| Jeton | Paylaşılan jeton tel üzerinden **gönderilmez**; yalnızca parmak izi ve imza gider |
| Tekrar saldırısı | 5 dakikalık saat sapması toleransı + nonce önbelleği; nonce imza doğrulandıktan sonra saklanır |
| Kaba kuvvet | IP başına 8 başarısız deneme / 60 saniye ve sınırlı eşzamanlı el sıkışma |
| Mesaj bütünlüğü | Her dosya aktarımında SHA-256; uyuşmazlıkta geçici dosya silinir |
| Çerçeve güvenliği | 4 bayt uzunluk, 32 MiB üst sınır, katı UTF-8/JSON doğrulaması |
| Denetim bütünlüğü | Her kayıtta `prev` ve `hash`; `audit verify` zinciri yeniden hesaplar |
| Gizli bilgi | Gömülü parola/IP yok; üretilen `config.json` sahip-only izinlerle yazılır |
| Ağ maruziyeti | Ajan yalnızca dışarı bağlanır; gelen port dinlemez |
| Yetki şeffaflığı | HELLO `admin`/`user` bildirir; prompt ve tabloda gösterilir |

> [!NOTE]
> Yerel hash zinciri, dosyanın kazara veya fırsatçı biçimde değiştirilmesini
> **tespit eder**, ancak sunucuda root yetkisi olan bir saldırgana karşı
> **kanıtlanamaz** kılmaz. Güçlü garanti için kayıtları değiştirilemez (WORM) bir
> uzak toplayıcıya gönderin.

### Platform desteği

| Platform | Durum |
|---|---|
| Windows 10/11 | Birincil geliştirme platformu; tüm test paketi yerelde çalıştırıldı |
| Linux (Ubuntu/Debian, systemd veya konteyner) | Desteklenir; `/proc`, `/sys`, POSIX sinyalleri ve standart kütüphane kullanılır. Aynı test paketi CI'da `ubuntu-latest` üzerinde çalışır |
| macOS | Telemetri sınırlıdır; TLS/filo protokolü platformdan bağımsızdır |

Linux notları: Python 3.10+ sürümünü dağıtımınızın paket yöneticisinden kurun,
ajanı ayrı ve en az yetkili bir servis hesabıyla çalıştırın ve yalnızca sunucu
portuna giden TCP trafiğine izin verin. Sunucu ve ajan `SIGTERM` aldığında
oturumları düzgün kapatır ve son denetim kaydını yazar. `systemd` servis
tanımları operatöre bırakılmıştır; iki program da normal ön plan süreçleridir.

### Kurulum ve hızlı başlangıç

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate
pip install -r requirements.txt
```

Aynı makinede:

```bash
# 1. terminal — filo sunucusu (ilk çalıştırmada sertifika ve jeton üretir)
python main.py

# 2. terminal — düğüm ajanı (config.json'dan host/port/jeton/CA okur)
python client.py --name web-01
```

> [!TIP]
> Sunucunun ilk çalıştırması üretilen jetonu bir kez gösterir ve `config.json`
> dosyasına yazar. Bu dosyayı gizli tutun; sonraki çalıştırmalarda jeton maskelenir.

Uzak düğüm için:

```bash
# Sunucuda, ajanların kullanacağı adresi kapsayan sertifika üretin
python main.py --generate-certs --san 10.20.30.40

# Sunucuyu başlatın
python main.py --host 0.0.0.0 --port 1536 --token "$NEPTICON_TOKEN"

# Düğümde: yalnızca ca.crt ve jetonu kopyalayın
python client.py --host 10.20.30.40 --port 1536 \
    --ca ca.crt --token "$NEPTICON_TOKEN" --name web-01
```

Üretimde yerel CA yerine kurumunuzun PKI sertifikalarını kullanın; `server.key`
dosyasını işletim sistemi izinleri veya bir sır yöneticisiyle koruyun.

### Yapılandırma

Öncelik sırası (yüksekten düşüğe): **CLI > `NEPTICON_*` ortam değişkenleri >
`config.json` > varsayılanlar**.

| Değişken | Anlamı |
|---|---|
| `NEPTICON_HOST` | Sunucu bağlanma adresi / ajan hedefi |
| `NEPTICON_PORT` | TLS portu (varsayılan `1536`) |
| `NEPTICON_TOKEN` | Paylaşılan HMAC jetonu |
| `NEPTICON_CERT` | Sunucu sertifikası; ajanda `NEPTICON_CA` yoksa güven kökü olarak da kullanılır |
| `NEPTICON_KEY` | Sunucu özel anahtarı |
| `NEPTICON_CA` | Ajanın sunucuyu doğruladığı CA sertifikası |
| `NEPTICON_CONFIG` | Ayar dosyası yolu |
| `NEPTICON_AUDIT_LOG` | Denetim kaydı yolu |
| `NEPTICON_DOWNLOADS` | Alınan dosyaların dizini |
| `NEPTICON_NAME` | Düğüm görünen adı |
| `NEPTICON_INSECURE` | `1` ise TLS doğrulaması kapatılır (yalnızca lab) |
| `NEPTICON_HEARTBEAT` | Kalp atışı aralığı (saniye) |
| `NEPTICON_REQUEST_TIMEOUT` | İstek zaman aşımı (saniye) |
| `NEPTICON_MAX_NODES` | Eşzamanlı en fazla düğüm |
| `NEPTICON_NO_COLOR` / `NEPTICON_NO_ANIMATIONS` | Görsel çıktıyı kapatır |
| `NEPTICON_VERBOSE` | Ayrıntılı günlük |

`config.example.json` dosya biçimini gösterir. Sunucu, jeton yapılandırılmamışsa
güçlü bir jeton üretip `config.json` dosyasına yazar (desteklenen platformlarda
`0600`). Jetonu yalnızca bir kez tam olarak gösterir; sonraki çalıştırmalarda
maskeler.

Kullanışlı bayraklar: `--host --port --token --cert --key --ca --config
--audit-log --downloads --heartbeat --request-timeout --transfer-timeout
--max-nodes --generate-certs [DIR] --force-certs --san NAME --no-color
--no-animations --verbose --version`. Ajana özel: `--name`, `--insecure`.

### Komut referansı

#### Filo konsolu (`Nepticon@Fleet`)

| Komut | Açıklama |
|---|---|
| `list` / `nodes` | Tüm düğümleri canlı ping'leyerek ID, hostname, IP:port, OS, yetki, uptime, gecikme ve durumla listeler |
| `health-all` / `metrics-all` / `fleet-health` | Tüm düğümlerden eşzamanlı telemetri toplayıp tek özet tablo basar |
| `broadcast <komut>` | Aynı bakım komutunu tüm düğümlerde eşzamanlı çalıştırır; düğüm bazlı çıktı ve özet verir |
| `select <id\|hostname>` | Tek düğümün etkileşimli yönetim oturumuna geçer |
| `audit [sayı]` | Son denetim kayıtlarını gösterir (varsayılan 20, en fazla 500) |
| `audit verify` | SHA-256 denetim zincirini doğrular |
| `status` | Yapılandırma, TLS parmak izi, düğüm sayısı, uptime ve denetim durumu |
| `help` | Komut referansı |
| `banner` / `clear` | Banner'ı yeniden basar / ekranı temizler |
| `quit` / `exit` | Sunucuyu düzgün biçimde kapatır |

#### Düğüm kabuğu (`Nepticon@Node[hostname]`)

| Komut | Açıklama |
|---|---|
| `health` / `metrics` | Anlık CPU, yük, RAM, disk, uptime, Python/OS ve ağ arayüzleri |
| `sysinfo` | Çekirdek, Python, kullanıcı, yetki, PID, çalışma dizini, açılış zamanı |
| `ps [n]` | Bellek kullanımına göre ilk `n` süreç (varsayılan 20, en fazla 100) |
| `env` | Gizli görünen adları maskelenmiş ortam değişkenleri + servis/çalışma bağlamı |
| `cd <yol>` / `pwd` | Ajanın çalışma dizinini değiştirir/sorgular |
| `upload <yerel> [uzak]` | Sunucu → düğüm; 64 KiB parça, ilerleme, SHA-256 doğrulama |
| `download <uzak> [yerel]` | Düğüm → sunucu; 64 KiB parça, ilerleme, SHA-256 doğrulama |
| `exec <komut>` | Açıkça kabuk komutu çalıştırır (tanınmayan girdiler de komut olarak çalıştırılır) |
| `disconnect` | Oturumu düşürür; ajan otomatik yeniden bağlanır |
| `shutdown --force` | Ajan sürecini sonlandırır (`--force` zorunlu) |
| `back` / `exit` / `quit` | Filo konsoluna döner |
| `help` / `banner` / `clear` | Görsel yardımcılar |

> [!TIP]
> Dosya yönleri **sunucu bakış açısıyla** adlandırılır: `upload` sunucudan düğüme
> gönderir, `download` düğümden sunucuya çeker. İndirilenler `--downloads`
> (varsayılan `./downloads`) dizinine benzersiz adla yazılır; uzak yol verilmeyen
> yüklemeler ajanın indirme dizinine düşer.

### Tel protokolü

Her mesaj, 4 bayt big-endian uzunluk öneki ve ardından UTF-8 JSON zarfıdır:

```text
┌──────────────────┬──────────────────────────────────────┐
│ uint32 uzunluk N │ N bayt UTF-8 JSON zarfı              │
└──────────────────┴──────────────────────────────────────┘

{"v":1,"type":"REQUEST","id":"…","ts":1770000000.0,
 "data":{"op":"exec","args":{"command":"uptime"}}}
```

Mesaj tipleri: `HELLO`, `WELCOME`, `AUTH_FAIL`, `REQUEST`, `RESPONSE`, `PING`,
`PONG`, `FILE_BEGIN`, `FILE_CHUNK`, `FILE_END`, `FILE_ABORT`, `GOODBYE`.
Dosya parçaları base64 taşır; alıcı sıra numarası, bildirilen boyut ve SHA-256
özetini doğrular.

HELLO şu kanonik metin üzerinden imzalanır:

```text
nepticon-hello-v1\n<ajan_sürümü>\n<hostname>\n<nonce>\n<unix_zaman>
```

`HMAC-SHA256(paylaşılan_jeton, kanonik_metin)` ile. Sunucu ayrıca jeton parmak
izini, zaman sapmasını ve nonce tazeliğini doğrular.

### Denetim kaydı

Varsayılan olarak `logs/audit.jsonl` dosyasına her bağlantı, komut, filo
işlemi, oturum seçimi ve dosya aktarımı yazılır. Kayıtlar yalnızca üst veri
içerir; komut çıktısı saklanmaz. Her kayıt önceki kaydın SHA-256 özetini taşır:

```json
{"ts":"2026-11-02T18:31:04.120Z","event":"command","severity":"info",
 "actor":"fleet-console","node":"web-01","peer":"10.20.30.5:49152",
 "detail":{"command":"systemctl restart nginx","ok":true,
           "exit_code":0,"duration_ms":812.4},
 "prev":"…64 hex…","hash":"…64 hex…"}
```

> [!NOTE]
> `audit verify` zinciri yeniden hesaplar ve ilk bozuk satırı bildirir. Daha güçlü
> değiştirilemezlik için dosyayı harici bir append-only toplayıcıya gönderin.

### Kullanım senaryoları

1. **Sabah filo triyajı:** `health-all` → disk/RAM baskısı olan düğümü `select`
   ile açın → `health`, `ps 15`, `env` ile servis bağlamını inceleyin.
2. **Bakım penceresi:** önce tek düğümde `select` + komutla doğrulayın, sonra
   `broadcast systemctl restart nginx` çalıştırın, ardından `health-all` ile
   sonucu kontrol edin.
3. **Olay kanıtı toplama:** `download /var/log/nginx/error.log` ile dosyayı
   SHA-256 doğrulamalı alın; denetim kaydında tam özet ve bayt sayısı kalır.
4. **Kontrollü dağıtım:** `upload` ile artefaktı gönderin, `broadcast` ile
   bütünlük kontrolü yapın; aktarım geçici dosya + `os.replace` ile atomiktir.

### Testler

```bash
python -m unittest discover -s tests -v
```

Test paketi `127.0.0.1` üzerinde gerçek TLS sunucusu ve ajanı başlatır; 300/600
KB'lik `{`/`}` içeren çerçeveleri, HMAC el sıkışmasını, yanlış jeton reddini,
JSON/`%s`/`{0}` çıktılı komutları, eşzamanlı `broadcast`/`health-all` işlemlerini,
telemetriyi, gizli değişken maskelemeyi, SHA-256 doğrulamalı 64 KiB parçalı
aktarımı, denetim zinciri ve kurcalama tespitini, sunucu yeniden başladıktan
sonra ajanın yeni soketle yeniden bağlanmasını doğrular (14 test).

### Sınırlamalar

> [!CAUTION]
> Jetonu bilen herkes tüm bağlı düğümleri yönetebilir; RBAC veya onay akışı
> yoktur. Ajanı ayrı ve en az yetkili bir hesapla çalıştırın, jetonu ve CA'yı
> gizli tutun ve `--insecure` seçeneğini asla izole olmayan ağlarda kullanmayın.

- Nepticon tam bir yapılandırma yönetimi (Ansible/Puppet) yerine geçmez; RBAC,
  onay akışı ve çoklu operatör izolasyonu yoktur. Jetonu bilen herkes tüm
  bağlı düğümleri yönetebilir.
- Komutlar etkileşimsizdir (PTY yoktur); interaktif kabuk için SSH kullanın.
- Ajan, çalıştığı servis hesabının yetkilerine sahiptir. Ayrı ve en az yetkili
  bir hesap kullanın; yetki seviyesi arayüzde görünür.
- Telemetri istek üzerine örneklenir; zaman serisi veritabanı değildir.
- Windows'ta `ctypes` Win32, Linux'ta `/proc` ve `/sys` kullanılır; macOS desteği
  sınırlıdır. Konteynerlerde ana makine metrikleri kısıtlı olabilir.
- Yerel hash zinciri kurcalamayı tespit eder, ancak root yetkili saldırgana karşı
  kanıt sağlamaz; kayıtları harici bir WORM sistemine gönderin.
- Üretilen sertifikalar lab/kurum içi kullanım içindir. Üretimde PKI kullanın ve
  `--insecure` seçeneğini asla izole olmayan ağlarda kullanmayın.

### Lisans ve emeği geçenler

Nepticon [MIT Lisansı](LICENSE) ile açık kaynak olarak yayımlanmıştır. Telif
hakkı (c) 2026 xd4rch. Nepticon v1.2 görsel kimliği ve orijinal “quartrinary”
banner'ı korunmuştur.

Güvenlik açıklarını genel bir issue yerine GitHub Security Advisories üzerinden
özel olarak bildirin; ayrıntılar [SECURITY.md](SECURITY.md) dosyasındadır.
