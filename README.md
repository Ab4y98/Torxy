# Torxy - Burp Suite Tor Proxy Extension

Burp Suite extension that routes all traffic through Tor with automatic IP rotation every 10 seconds. Compatible with macOS, Linux, and Windows.

## Prerequisites

- **Burp Suite** Professional or Community Edition
- **Jython standalone JAR** ([download](https://www.jython.org/download))

## Setup

### 1. Download Tor binaries (one-time)

```bash
cd Torxy
./setup.sh
```

This downloads the Tor Expert Bundle for all platforms into `bin/`. Requires `curl` and `tar` (both native on macOS, Linux, and Windows 10+).

> **macOS note:** If you get SSL errors with the system curl, install Homebrew's curl first: `brew install curl`. The script will auto-detect and use it.

### 2. Load in Burp Suite

1. Go to **Extensions** > **Extensions settings** > **Python environment**
2. Set the path to the Jython standalone JAR (one-time)
3. Go to **Extensions** > **Installed** > **Add**
4. Extension type: **Python**, select `torxy.py`
5. The **Torxy** tab appears in Burp

## Usage

1. Open the **Torxy** tab
2. Click **Start Tor**
3. Configure Burp's SOCKS proxy:
   - **Settings** > **Network** > **Connections** > **SOCKS Proxy**
   - Host: `127.0.0.1`, Port: `9050`
   - Check **Use SOCKS proxy**
4. All Burp traffic now routes through Tor with IP rotation every 10 seconds

## Project Structure

```
Torxy/
  torxy.py              Burp extension (single file)
  setup.sh              Downloads Tor binaries for all platforms
  bin/
    macos-aarch64/tor/  macOS Apple Silicon
    macos-x86_64/tor/   macOS Intel
    linux-x86_64/tor/   Linux x86_64
    windows-x86_64/tor/ Windows x86_64
```

## Git LFS

Binary files in `bin/` are tracked with Git LFS. After cloning:

```bash
git lfs install
git lfs pull
```

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| SOCKS port | 9050 | Tor SOCKS proxy port |
| Control port | 9051 | Tor control port for circuit management |
| Rotation interval | 10s | Seconds between IP rotations (Tor minimum) |
