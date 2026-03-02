# Torxy - Burp Suite Tor Proxy Extension


![Torxy in Burp Suite](https://gcdnb.pbrd.co/images/V1TEynBtbGgx.png?o=1)
![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)

Burp Suite extension that routes all traffic through Tor with automatic IP rotation every 10 seconds. Compatible with macOS (Apple Silicon & Intel), Linux, and Windows.

## Prerequisites

- **Burp Suite** Professional or Community Edition
- **Jython standalone JAR** ([download](https://www.jython.org/download))

## Setup

1. Go to **Extensions** > **Extensions settings** > **Python environment**
2. Set the path to the Jython standalone JAR (one-time)
3. Go to **Extensions** > **Installed** > **Add**
4. Extension type: **Python**, select `torxy.py`
5. The **Torxy** tab appears in Burp

Tor is downloaded automatically on first run. No manual installation required.

## Usage

1. Open the **Torxy** tab
2. Click **Start Tor** — Torxy will locate or auto-download the Tor Expert Bundle
3. Configure Burp's SOCKS proxy:
   - **Settings** > **Network** > **Connections** > **SOCKS Proxy**
   - Host: `127.0.0.1`, Port: `9050`
   - Check **Use SOCKS proxy**
4. All Burp traffic now routes through Tor with IP rotation every 10 seconds

You can also provide a custom Tor binary path using the text field in the Controls panel.

## How It Works

- **Auto-download**: If Tor isn't installed on your system, Torxy downloads the official Tor Expert Bundle from `dist.torproject.org` and stores it in `~/.BurpSuite/bapps/torxy/`.
- **macOS Gatekeeper**: Downloaded binaries are automatically ad-hoc code signed to prevent macOS from blocking them.
- **IP rotation**: A background thread requests a new Tor circuit via the control port every 10 seconds, cycling your exit IP.
- **Control port auth**: Torxy uses hashed password authentication (falls back to cookie auth if hashing fails).

## Project Structure

```
Torxy/
  torxy.py    Burp extension (single file)
  setup.sh    Optional script to pre-download Tor bundles for all platforms
```

Runtime files are stored in:
- `~/.BurpSuite/bapps/torxy/` — downloaded Tor binary + libs
- `$TMPDIR/torxy_data/` — Tor data directory and torrc (ephemeral)

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| SOCKS port | 9050 | Tor SOCKS proxy port |
| Control port | 9051 | Tor control port for circuit management |
| Rotation interval | 10s | Seconds between IP rotations |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Tor not found | Torxy auto-downloads it. If download fails, install Tor manually and enter the path in the Controls panel. |
| "Tor exited before full bootstrap" | On macOS, ensure `codesign` is available (ships with Xcode CLI tools: `xcode-select --install`). |
| Port conflict on 9050/9051 | Another Tor instance or service may be using these ports. Stop it first. |
| Download fails behind proxy | Torxy tries `curl` first, then falls back to Java HTTPS. Ensure outbound access to `dist.torproject.org`. |

---

![Torxy in Burp Suite](https://gcdnb.pbrd.co/images/eU3WnRuzu25h.png?o=1)
