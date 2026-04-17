# NexNull — DPI Bypass Proxy

**Advanced SNI Spoofing via WinDivert TCP/IP Header Manipulation**

> 🇬🇧 English | 🇮🇷 [فارسی](README.fa.md)

---

## What is NexNull?

NexNull is a production-grade DPI bypass proxy for Windows that helps users in Iran circumvent **Deep Packet Inspection (DPI)** used by Iranian ISPs to block internet access.

It works by intercepting the TCP handshake at the kernel level using **WinDivert** and injecting a fake TLS ClientHello with a spoofed SNI pointing to a whitelisted domain. The DPI system sees the allowed domain and permits the connection. The real server ignores the out-of-window packet. Real traffic then flows freely.

> Based on the original work by **[patterniha](https://github.com/patterniha/SNI-Spoofing)** — full credit and respect to the original author.

---

## How It Works

1. NexNull listens on a local port (`LISTEN_PORT`)
2. A client connects to the proxy
3. The proxy opens an outgoing TCP connection to `CONNECT_IP:CONNECT_PORT`
4. WinDivert intercepts the TCP handshake at the kernel level
5. After the 3-way handshake ACK, NexNull injects a fake TLS ClientHello with:
   - Spoofed SNI = `FAKE_SNI` (a whitelisted domain)
   - Deliberately wrong TCP sequence number: `seq = (syn_seq + 1 - len(fake_data)) & 0xFFFFFFFF`
   - Real browser fingerprint (Chrome / Firefox / Safari / Edge) with GREASE values
   - Human-like Gaussian-distributed injection timing
   - Randomized TTL to mimic a real host at network distance
   - Padding jitter (±12 bytes) to avoid size fingerprinting
6. DPI sees the whitelisted SNI and allows the connection
7. The real server ignores the out-of-window packet
8. The server ACKs the fake packet — bypass confirmed
9. Full bidirectional relay starts

**Why does the wrong sequence number work?**

DPI systems perform **stateless or shallow inspection** — they read the first data packet and check the SNI field without fully validating TCP sequence numbers. The target server is stateful and correctly rejects the out-of-window packet. DPI is fooled, the server is unaffected.

---

## Architecture Diagram

```
  CLIENT                    NexNull                    DPI              TARGET
    |                          |                        |                  |
    |--- TCP connect --------->|                        |                  |
    |                          |--- SYN seq=X -------->|----------------->|
    |                          |<-- SYN-ACK seq=Y -----|<-----------------|
    |                          |--- ACK seq=X+1 ------>|----------------->|
    |                          |                        |                  |
    |                    [WinDivert injects]            |                  |
    |                          |--- PSH seq=X+1-N ---->|                  |
    |                          |   fake TLS ClientHello |  SNI=hcaptcha   |
    |                          |   SNI = FAKE_SNI       |  ALLOW! ✓       |
    |                          |   browser fingerprint  |                  |
    |                          |   humanized timing     |                  |
    |                          |   spoofed TTL          |                  |
    |                          |   (wrong seq, ignored  |                  |
    |                          |    by server)          |                  |
    |                          |<-- ACK ack=X+1 --------|<-----------------|
    |                          |                        |                  |
    |<====== Full bidirectional relay =================>|=================>|
```

---

## Project Structure

```
NexNull/
├── main.py                    # Entry point — admin check, banner, serve loop
├── logger_setup.py            # 256-color logging, VERBOSE level, WinError 6 filter
├── facts.py                   # 63 fun facts about Iran's firewall (Nex-chan)
├── config.json                # Runtime configuration
├── main.spec                  # PyInstaller build spec
├── requirements.txt           # Python dependencies
│
├── core/
│   ├── config.py              # Config dataclass + loader + validation
│   ├── connection.py          # MonitorConnection — TCP sequence state tracker
│   ├── relay.py               # Async relay, rate limiting, idle timeout, SNI logging
│   └── stats.py               # Stats counters, per-SNI tracking, title bar updater
│
├── bypass/
│   ├── injector.py            # WinDivert base class + auto-reconnect with backoff
│   └── fake_tcp.py            # wrong_seq bypass, humanized timing, TTL spoofing
│
└── utils/
    ├── network_tools.py       # Local interface IP detection
    ├── packet_templates.py    # TLS ClientHello builder using browser profiles
    ├── fingerprint.py         # Browser TLS fingerprint profiles (Chrome/Firefox/Safari/Edge)
    ├── humanize.py            # Human-like timing model (Gaussian + Weibull jitter)
    └── sni_extractor.py       # TLS SNI parser, fragmentation-aware, IDN support
```

---

## Requirements

- Windows 10 / 11 (64-bit)
- Administrator privileges (WinDivert requires kernel-level access)
- Python 3.11+ (for running from source)
- `pydivert` (bundled in the prebuilt `.exe`)

---

## Installation

### Option A — Run the prebuilt `.exe`

1. Download `main.exe`
2. Place `config.json` in the **same folder** as `main.exe`
3. Right-click `main.exe` → **Run as administrator**

### Option B — Run from source

```bash
pip install -r requirements.txt
python main.py
```

> Must be run as Administrator.

### Build the `.exe` yourself

```bash
pip install pyinstaller
python -m PyInstaller main.spec
```

Output: `dist\main.exe` — copy `config.json` next to it.

---

## Configuration (`config.json`)

```json
{
  "LISTEN_HOST":      "0.0.0.0",
  "LISTEN_PORT":      40443,
  "CONNECT_IP":       "104.19.229.21",
  "CONNECT_PORT":     443,
  "FAKE_SNI":         "hcaptcha.com",

  "BYPASS_TIMEOUT":   2.0,
  "FAKE_DELAY_MS":    1.0,
  "CONNECT_TIMEOUT":  5.0,

  "RECV_BUFFER":      65536,
  "MAX_CONNECTIONS":  0,
  "IDLE_TIMEOUT":     120,
  "RATE_LIMIT":       0,

  "BROWSER_PROFILE":  "random",
  "TTL_SPOOF":        true,

  "LOG_LEVEL":        "INFO",
  "LOG_CLIENT_SNI":   true,
  "LOG_FILE":         "",
  "STATS_INTERVAL":   60
}
```

| Key | Default | Description |
|---|---|---|
| `LISTEN_HOST` | `"0.0.0.0"` | Local address to listen on (`0.0.0.0` = all interfaces) |
| `LISTEN_PORT` | `40443` | Local port the proxy listens on |
| `CONNECT_IP` | — | Target server IP to connect to |
| `CONNECT_PORT` | `443` | Target server port (usually 443) |
| `FAKE_SNI` | `"hcaptcha.com"` | Spoofed SNI domain — must be a whitelisted domain |
| `BYPASS_TIMEOUT` | `2.0` | Seconds to wait for bypass handshake to complete |
| `FAKE_DELAY_MS` | `1.0` | Base delay (ms) before injecting fake packet — humanized with Gaussian jitter |
| `CONNECT_TIMEOUT` | `5.0` | TCP connect timeout in seconds |
| `RECV_BUFFER` | `65536` | Bytes per `recv()` call |
| `MAX_CONNECTIONS` | `0` | Max concurrent connections — `0` = unlimited |
| `IDLE_TIMEOUT` | `120` | Seconds of relay inactivity before closing — `0` = disabled |
| `RATE_LIMIT` | `0` | Max new connections per second per IP — `0` = disabled |
| `BROWSER_PROFILE` | `"random"` | TLS fingerprint profile: `chrome` / `firefox` / `safari` / `edge` / `random` |
| `TTL_SPOOF` | `true` | Randomize TTL on fake packet to mimic a real host at network distance |
| `LOG_LEVEL` | `"INFO"` | Log verbosity: `DEBUG` / `VERBOSE` / `INFO` / `WARNING` / `ERROR` |
| `LOG_CLIENT_SNI` | `true` | Log the real destination SNI from each client's TLS hello |
| `LOG_FILE` | `""` | Path to write a plain-text log file — empty = disabled |
| `STATS_INTERVAL` | `60` | Seconds between automatic stats log entries — `0` = disabled |

---

## Log Levels

| Level | Badge | What is logged |
|---|---|---|
| `DEBUG` | `[.]` | All packet-level details, socket operations, state transitions |
| `VERBOSE` | `[>]` | Connection-level detail between DEBUG and INFO |
| `INFO` | `[+]` | Connection open/close, SNI, relay start/stop, stats — **recommended** |
| `WARNING` | `[!]` | Failed connections, bypass failures, rate limit hits |
| `ERROR` | `[x]` | Serious errors only |
| `CRITICAL` | `[!!]` | Fatal errors |

---

## Log Format

```
[08:15:05] [+]   [INFO    ] [relay]   CONN  127.0.0.1:52100  [active=3  total=47]
[08:15:05] [+]   [INFO    ] [relay]   SNI  example.com                        from 127.0.0.1
[08:15:05] [.]   [DEBUG   ] [fake_tcp] Using browser profile: Chrome/124
[08:15:05] [.]   [DEBUG   ] [fake_tcp] Fake injected  192.168.1.5:52101 -> 104.19.229.21:443  seq=...  ttl=56
[08:15:05] [+]   [INFO    ] [relay]   RELAY 127.0.0.1:52100  <->  104.19.229.21:443
[08:15:05] [+]   [INFO    ] [relay]   CLOSE 127.0.0.1:52100
[08:15:05] [+]   [INFO    ] [stats]   Stats  uptime: 5m 23s    total: 47     active: 3  ...
[08:15:05] [+]   [INFO    ] [stats]   Top SNIs: example.com(23)  google.com(12)  ...
```

---

## Title Bar

The Windows console title bar updates every 2 seconds with live stats:

```
NexNull  |  Req: 47  Active: 3  Failed: 2  Up: 12.3MB  Dn: 45.6MB  5m 23s
```

---

## Technical Details

### Browser TLS Fingerprinting (`utils/fingerprint.py`)

NexNull builds fake ClientHellos that match real browser TLS fingerprints:

| Profile | Cipher Suites | Extensions | GREASE | ALPN |
|---|---|---|---|---|
| `chrome` | Chrome 124 order | Chrome 124 order | Yes | h2, http/1.1 |
| `firefox` | Firefox 125 order | Firefox 125 order | No | h2, http/1.1 |
| `safari` | Safari 17 order | Safari 17 order | No | h2, http/1.1 |
| `edge` | Edge 124 order | Edge 124 order | Yes | h2, http/1.1 |
| `random` | Different browser each connection | — | — | — |

**GREASE values** (RFC 8701) are injected into cipher suites and extensions — exactly what Chrome and Edge do to test that DPI systems ignore unknown values.

### Human-Like Timing (`utils/humanize.py`)

The fake packet injection delay is not a fixed `sleep(1ms)`. It uses:

- **Gaussian component**: centered on `FAKE_DELAY_MS`, σ = 30% — models TLS stack processing time
- **Weibull tail** (8% probability): models occasional longer pauses (GC, scheduler jitter, ~5-20ms)
- **Adaptive**: measures elapsed time since SYN, only sleeps the remaining delay

This makes the timing distribution indistinguishable from a real browser's first data packet.

### TTL Spoofing (`bypass/fake_tcp.py`)

When `TTL_SPOOF: true`, the fake packet gets a randomized TTL:
- Base: 64 (Linux/macOS) or 128 (Windows) — chosen randomly
- Minus 1-8 hops — simulates a real host at network distance

This prevents DPI from detecting the fake packet by its TTL value.

### Sequence Number Calculation

```python
fake_seq = (syn_seq + 1 - len(fake_payload)) & 0xFFFFFFFF
```

Places the fake packet's data range *before* the next expected byte — outside the server's receive window. The server silently discards it. DPI sees it first and records the SNI.

### WinDivert Filter

```
tcp and (
  (ip.SrcAddr == LOCAL_IP and ip.DstAddr == TARGET_IP)
  or
  (ip.SrcAddr == TARGET_IP and ip.DstAddr == LOCAL_IP)
)
```

Only packets on the specific `local ↔ target` path are intercepted. All other traffic passes through unmodified.

### Thread Model

| Component | Role |
|---|---|
| Main thread | `asyncio` event loop — accepts connections, manages relay tasks |
| WinDivert thread | Daemon thread — intercepts and injects packets synchronously |
| Thread pool (64 workers) | Handles fake-send tasks with humanized timing |
| `asyncio.Event` (`t2a_event`) | Signals from WinDivert thread to async loop when bypass completes |

### WinDivert Auto-Reconnect

If the WinDivert driver crashes or the handle is lost, the injector automatically reconnects with exponential backoff (0.5s → 30s max). No manual restart needed.

### SNI Extraction (`utils/sni_extractor.py`)

- Accumulates TCP chunks until a complete TLS ClientHello is parseable (up to 16 KB)
- Handles fragmented ClientHellos spanning multiple TCP packets
- UTF-8 decoding with ASCII fallback for international domain names (IDN)
- Iterates all extensions in any order — not just the first

---

## Credits

Based on the original work by **[patterniha](https://github.com/patterniha/SNI-Spoofing)** — a developer dedicated to building tools that help people in Iran access a free and open internet. Full respect and credit to the original author for the core idea, architecture, and implementation.

- **Telegram:** [@patterniha](https://t.me/patterniha)
- **Channel:** [t.me/projectXhttp](https://t.me/projectXhttp)

### Support the Developer

If NexNull helps you access the free internet, please consider supporting patterniha.

- **USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
- **USDT (TRC20):** `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`

---

## License

GPL-3.0 — see [LICENSE](LICENSE)
