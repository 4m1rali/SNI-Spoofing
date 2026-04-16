# SNI-Spoofing

**Bypass DPI with IP/TCP-Header manipulation**

> 🇬🇧 English | 🇮🇷 [فارسی](README.fa.md)

---

## 🇬🇧 English

### What is SNI-Spoofing?

SNI-Spoofing is a tool that bypasses **Deep Packet Inspection (DPI)** used by ISPs and network censorship systems (such as those in Iran) to block internet access. It works by manipulating IP and TCP headers at a low level using the **WinDivert** driver to intercept and modify packets in real time.

The core technique sends a **fake TLS ClientHello** with a spoofed SNI (Server Name Indication) field containing a whitelisted domain, tricking DPI systems into allowing the connection through. The real traffic then flows freely over the established connection.

### How It Works

1. The tool listens on a local port (configured in `config.json`)
2. Incoming connections are intercepted and a fake TLS ClientHello is crafted with a spoofed SNI
3. WinDivert intercepts outgoing packets and injects the fake data with a manipulated sequence number (`wrong_seq` bypass method)
4. The DPI system sees a whitelisted SNI and allows the TCP handshake
5. Once the bypass handshake completes, full bidirectional relay begins between the client and target server

### Architecture Diagram

```
  ┌─────────────┐                                          ┌─────────────────┐
  │   Client    │                                          │  Target Server  │
  │ (Browser,   │                                          │ (e.g. Cloudflare│
  │  App, etc.) │                                          │  104.19.229.21) │
  └──────┬──────┘                                          └────────┬────────┘
         │                                                          │
         │  TCP connect to 127.0.0.1:40443                         │
         ▼                                                          │
  ┌─────────────────────────────────────────────────────┐          │
  │                  SNI-Spoofing (main.py)              │          │
  │                                                     │          │
  │  ┌──────────────────────────────────────────────┐   │          │
  │  │           Async Relay Loop (asyncio)          │   │          │
  │  │                                              │   │          │
  │  │  1. Accept incoming connection               │   │          │
  │  │  2. Build fake TLS ClientHello               │   │          │
  │  │     SNI = "mci.ir" (whitelisted domain)      │   │          │
  │  │  3. Open outgoing socket → CONNECT_IP:443    │───┼──────────┤
  │  │  4. Wait for bypass handshake signal         │   │          │
  │  │  5. Start bidirectional relay                │   │          │
  │  └──────────────────────────────────────────────┘   │          │
  │                       ▲  signal                     │          │
  │                       │  (t2a_event)                │          │
  │  ┌────────────────────┴─────────────────────────┐   │          │
  │  │         WinDivert Thread (fake_tcp.py)        │   │          │
  │  │                                              │   │          │
  │  │  Intercepts all TCP packets on the           │   │          │
  │  │  local_ip ↔ target_ip path                   │   │          │
  │  │                                              │   │          │
  │  │  OUTBOUND packet flow:                       │   │          │
  │  │  ┌──────────────────────────────────────┐    │   │          │
  │  │  │ [SYN]  → pass through               │    │   │          │
  │  │  │ [ACK]  → pass through               │    │   │          │
  │  │  │         + spawn fake_send_thread     │    │   │          │
  │  │  └──────────────────────────────────────┘    │   │          │
  │  │                                              │   │          │
  │  │  fake_send_thread (1ms delay):               │   │          │
  │  │  ┌──────────────────────────────────────┐    │   │          │
  │  │  │ Inject fake ClientHello packet with  │    │   │          │
  │  │  │ seq_num = syn_seq + 1 - len(payload) │    │   │          │
  │  │  │ (deliberately WRONG sequence number) │    │   │          │
  │  │  └──────────────────────────────────────┘    │   │          │
  │  │                                              │   │          │
  │  │  INBOUND packet flow:                        │   │          │
  │  │  ┌──────────────────────────────────────┐    │   │          │
  │  │  │ [SYN-ACK] → pass through             │    │   │          │
  │  │  │ [ACK]     → if fake was ACKed:        │    │   │          │
  │  │  │             signal relay to start     │    │   │          │
  │  │  └──────────────────────────────────────┘    │   │          │
  │  └──────────────────────────────────────────────┘   │          │
  └─────────────────────────────────────────────────────┘          │
                                                                    │
```

### Packet-Level Diagram: `wrong_seq` Bypass

```
  CLIENT          SNI-Spoofing            DPI System          TARGET SERVER
    │                   │                     │                      │
    │──── connect ──────▶                     │                      │
    │                   │                     │                      │
    │              [outgoing socket]          │                      │
    │                   │──── [SYN] seq=X ───▶│──────────────────────▶
    │                   │◀─── [SYN-ACK] seq=Y,ack=X+1 ──────────────│
    │                   │──── [ACK] seq=X+1 ─▶│──────────────────────▶
    │                   │                     │                      │
    │                   │  (WinDivert injects fake packet here)      │
    │                   │                     │                      │
    │                   │──── [PSH] ─────────▶│                      │
    │                   │  seq = X+1-len(fake)│                      │
    │                   │  payload = fake TLS │  DPI sees SNI        │
    │                   │  ClientHello with   │  "mci.ir" ✓          │
    │                   │  SNI="mci.ir"       │  ALLOW connection    │
    │                   │                     │                      │
    │                   │  (server ignores — out of TCP window)      │
    │                   │◀─── [ACK] ack=X+1 ──│◀─────────────────────│
    │                   │                     │                      │
    │                   │  bypass signal ✓    │                      │
    │                   │                     │                      │
    │══════════════ Full bidirectional relay begins ════════════════▶│
    │◀═════════════ (real TLS handshake + data flows freely) ════════│
    │                   │                     │                      │
```

### Key Technical Details

**Why does the wrong sequence number work?**

The DPI system performs **stateless or shallow inspection** — it reads the first data packet on a connection and checks the SNI field, but does not fully validate TCP sequence numbers. The target server is stateful and correctly rejects the out-of-window packet. The net result: DPI is fooled, the server is unaffected.

**The fake TLS ClientHello (`utils/packet_templates.py`)**

A real, well-formed TLS 1.3 ClientHello is crafted with:
- Random 32-byte `random` field
- Random 32-byte `session_id`
- Random 32-byte `key_share`
- The spoofed SNI set to the whitelisted domain (e.g. `mci.ir`)
- Padding extension to normalize packet length (519 bytes total)

The packet looks completely legitimate to any TLS inspector — only the SNI is fake.

**Sequence number math**

```
fake_seq = (syn_seq + 1 - len(fake_payload)) & 0xffffffff
```

This places the fake packet's data range *before* the next expected byte, putting it outside the server's receive window. The server silently discards it. DPI sees it first and records the SNI.

**WinDivert filter**

```
tcp and (
  (ip.SrcAddr == LOCAL_IP and ip.DstAddr == TARGET_IP)
  or
  (ip.SrcAddr == TARGET_IP and ip.DstAddr == LOCAL_IP)
)
```

Only packets on the specific local↔target path are intercepted. All other traffic passes through unmodified.

**Thread model**

- Main thread: `asyncio` event loop — accepts connections, manages relay tasks
- WinDivert thread: daemon thread — intercepts and injects packets synchronously
- Communication: `asyncio.Event` (`t2a_event`) signals from WinDivert thread to async loop when bypass handshake completes

### Credits

This project is based on the original work of **[@patterniha](https://t.me/patterniha)** — a developer dedicated to building tools that help people in Iran access a free and open internet. Full respect and credit goes to them for the core idea, architecture, and implementation.

Original repository: [github.com/patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

### Requirements

- Windows 10 / 11 (64-bit)
- Python 3.11+ (for running from source)
- [WinDivert](https://reqrypt.org/windivert.html) (bundled via pydivert)
- **Administrator privileges** (required for packet interception)

### Installation & Usage

#### Option A — Run the prebuilt `.exe`

1. Download or build `main.exe`
2. Place `config.json` in the **same folder** as `main.exe`
3. Right-click `main.exe` → **Run as administrator**

#### Option B — Run from source

```bash
pip install -r requirements.txt
python main.py
```
> Must be run as Administrator.

#### Build the `.exe` yourself

```bash
pip install pyinstaller
python -m PyInstaller main.spec
```
Output: `dist\main.exe` — copy `config.json` next to it.

### Configuration (`config.json`)

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "FAKE_SNI": "mci.ir",
  "CONNECT_IP": "104.19.229.21",
  "CONNECT_PORT": 443
}
```

| Key | Description |
|---|---|
| `LISTEN_HOST` | Local address to listen on (`0.0.0.0` = all interfaces) |
| `LISTEN_PORT` | Local port your proxy listens on |
| `FAKE_SNI` | The spoofed SNI domain sent to fool DPI (use a whitelisted domain) |
| `CONNECT_IP` | Target server IP to connect to |
| `CONNECT_PORT` | Target server port (usually `443`) |

### Project Structure

```
SNI-Spoofing/
├── main.py                 # Entry point, async relay loop
├── fake_tcp.py             # FakeInjectiveConnection & FakeTcpInjector
├── injecter.py             # Abstract WinDivert packet injector base
├── monitor_connection.py   # TCP connection state tracker
├── logger_setup.py         # Colored logging setup
├── config.json             # Runtime configuration
├── main.spec               # PyInstaller build spec
├── requirements.txt        # Python dependencies
└── utils/
    ├── network_tools.py    # Network interface helpers
    └── packet_templates.py # TLS ClientHello / ServerHello builders
```

### Support the Developer

If this tool helps you access the free internet, please support [@patterniha](https://t.me/patterniha) — more projects are in development to help people in Iran bypass censorship.

- **USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
- **USDT (TRC20):** `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`
- **Telegram:** [@patterniha](https://t.me/patterniha)
- **Channel:** [projectXhttp](https://t.me/projectXhttp)

### License

GPL-3.0 — see [LICENSE](LICENSE)
