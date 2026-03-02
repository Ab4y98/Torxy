"""
Torxy - Burp Suite Tor Proxy Extension
Routes Burp traffic through Tor with automatic IP rotation every 10 seconds.
Compatible with macOS, Linux, and Windows.
Maintained by @ab4y98
"""

from burp import IBurpExtender, ITab, IExtensionStateListener

from javax.swing import (JPanel, JLabel, JButton, JTextArea, JScrollPane,
                          SwingUtilities, BorderFactory, BoxLayout, Box,
                          JTextField, JOptionPane)
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, Color, Font, FlowLayout
from java.lang import ProcessBuilder, System, String as JString
from java.io import (File, FileWriter, BufferedReader, InputStreamReader,
                      FileInputStream)
from java.net import Socket, URL, InetSocketAddress, Proxy
from java.util import ArrayList

import threading
import time
import os

EXTENSION_NAME = "Torxy"
SOCKS_PORT = 9050
CONTROL_PORT = 9051
ROTATION_INTERVAL = 10
CONTROL_PASSWORD = "torxy_ctrl_auth"
IP_CHECK_URL = "http://api.ipify.org"


# ---------------------------------------------------------------------------
# Tor process lifecycle: detection, start, stop
# ---------------------------------------------------------------------------

class TorManager(object):

    def __init__(self, extender, ext_dir):
        self.extender = extender
        self.process = None
        self.tor_binary = None
        self.data_dir = None
        self._ext_dir = ext_dir
        self._os = System.getProperty("os.name").lower()

    @property
    def is_windows(self):
        return "win" in self._os

    @property
    def is_mac(self):
        return "mac" in self._os or "darwin" in self._os

    @property
    def is_linux(self):
        return "nux" in self._os or "nix" in self._os

    # -- Detection --

    def _bundled_tor(self):
        arch = System.getProperty("os.arch").lower()
        if self.is_mac:
            tag = "macos-aarch64" if arch in ("aarch64", "arm64") else "macos-x86_64"
        elif self.is_linux:
            tag = "linux-x86_64"
        elif self.is_windows:
            tag = "windows-x86_64"
        else:
            return None
        name = "tor.exe" if self.is_windows else "tor"
        return os.path.join(self._ext_dir, "bin", tag, "tor", name)

    def find_tor(self):
        bundled = self._bundled_tor()
        if bundled:
            f = File(bundled)
            if f.exists() and f.isFile():
                self.tor_binary = bundled
                self.extender.log("Using bundled Tor: " + bundled)
                return bundled

        name = "tor.exe" if self.is_windows else "tor"
        candidates = []
        if self.is_mac:
            candidates = ["/opt/homebrew/bin/tor",
                          "/usr/local/bin/tor",
                          "/opt/local/bin/tor"]
        elif self.is_linux:
            candidates = ["/usr/bin/tor",
                          "/usr/local/bin/tor",
                          "/usr/sbin/tor"]
        elif self.is_windows:
            h = System.getProperty("user.home")
            pf = System.getenv("ProgramFiles") or "C:\\Program Files"
            px = System.getenv("ProgramFiles(x86)") or "C:\\Program Files (x86)"
            candidates = [
                os.path.join(h, "Desktop", "Tor Browser", "Browser",
                             "TorBrowser", "Tor", "tor.exe"),
                os.path.join(pf, "Tor", "tor.exe"),
                os.path.join(px, "Tor", "tor.exe"),
            ]

        for p in candidates:
            if File(p).exists():
                self.tor_binary = p
                self.extender.log("Found Tor: " + p)
                return p

        path_env = System.getenv("PATH")
        if path_env:
            sep = ";" if self.is_windows else ":"
            for d in path_env.split(sep):
                f = File(d, name)
                if f.exists():
                    self.tor_binary = f.getAbsolutePath()
                    self.extender.log("Found Tor in PATH: " + self.tor_binary)
                    return self.tor_binary

        self.extender.log("Tor not found. Run setup.sh to download bundled binaries.")
        return None

    # -- Process helpers --

    def _pb(self, cmd):
        lst = ArrayList()
        for c in cmd:
            lst.add(c)
        pb = ProcessBuilder(lst)
        if self.is_mac and self.tor_binary:
            lib_dir = File(self.tor_binary).getParent()
            if lib_dir:
                pb.environment().put("DYLD_LIBRARY_PATH", lib_dir)
        return pb

    def _hash_password(self):
        if not self.tor_binary:
            return None
        try:
            pb = self._pb([self.tor_binary, "--hash-password", CONTROL_PASSWORD])
            pb.redirectErrorStream(True)
            proc = pb.start()
            rdr = BufferedReader(InputStreamReader(proc.getInputStream()))
            hashed = None
            ln = rdr.readLine()
            while ln is not None:
                if ln.strip().startswith("16:"):
                    hashed = ln.strip()
                ln = rdr.readLine()
            proc.waitFor()
            return hashed
        except:
            return None

    # -- Start / Stop --

    def start(self):
        if self.process is not None:
            self.extender.log("Tor already running")
            return True
        if not self.tor_binary:
            self.extender.log("Tor binary not set")
            return False

        tmp = System.getProperty("java.io.tmpdir")
        self.data_dir = os.path.join(tmp, "torxy_data")
        File(self.data_dir).mkdirs()

        hashed = self._hash_password()
        if hashed:
            auth_line = "HashedControlPassword " + hashed
        else:
            auth_line = "CookieAuthentication 1"
        self.extender._use_cookie = (hashed is None)

        torrc = os.path.join(self.data_dir, "torrc")
        cfg = "SOCKSPort %d\nControlPort %d\nDataDirectory %s\n%s\n" % (
            SOCKS_PORT, CONTROL_PORT,
            self.data_dir.replace("\\", "/"),
            auth_line)

        fw = FileWriter(torrc)
        fw.write(cfg)
        fw.close()

        self.extender.log(
            "Starting Tor (SOCKS:%d  Control:%d)..." % (SOCKS_PORT, CONTROL_PORT))

        try:
            pb = self._pb([self.tor_binary, "-f", torrc])
            pb.redirectErrorStream(True)
            self.process = pb.start()

            def _watch():
                rdr = BufferedReader(
                    InputStreamReader(self.process.getInputStream()))
                ready = False
                ln = rdr.readLine()
                while ln is not None:
                    self.extender.log("[tor] " + ln)
                    if "Bootstrapped 100%" in ln:
                        ready = True
                        self.extender.on_tor_ready()
                    ln = rdr.readLine()
                if not ready:
                    self.extender.log("Tor exited before full bootstrap")
                self.extender.on_tor_stopped()

            t = threading.Thread(target=_watch)
            t.daemon = True
            t.start()
            return True

        except Exception as e:
            self.extender.log("Start failed: " + str(e))
            self.process = None
            return False

    def stop(self):
        if self.process:
            try:
                self.process.destroy()
            except:
                pass
            self.process = None
            self.extender.log("Tor process stopped")


# ---------------------------------------------------------------------------
# Tor control-port interface (authenticate, NEWNYM)
# ---------------------------------------------------------------------------

class TorController(object):

    def __init__(self, extender):
        self.extender = extender
        self.sock = None
        self.reader = None
        self._out = None
        self._lock = threading.Lock()

    def connect(self, use_cookie=False, data_dir=None):
        try:
            self.close()
            self.sock = Socket("127.0.0.1", CONTROL_PORT)
            self.sock.setSoTimeout(10000)
            self.reader = BufferedReader(
                InputStreamReader(self.sock.getInputStream(), "UTF-8"))
            self._out = self.sock.getOutputStream()

            if use_cookie and data_dir:
                cookie = self._read_cookie(
                    os.path.join(data_dir, "control_auth_cookie"))
                if cookie:
                    self._send("AUTHENTICATE " + cookie)
                else:
                    self.extender.log("Cookie file missing, trying empty auth")
                    self._send("AUTHENTICATE")
            else:
                self._send('AUTHENTICATE "' + CONTROL_PASSWORD + '"')

            resp = self.reader.readLine()
            if resp and resp.startswith("250"):
                self.extender.log("Control port authenticated")
                return True
            self.extender.log("Auth failed: " + str(resp))
            return False

        except Exception as e:
            self.extender.log("Control connect error: " + str(e))
            return False

    def _read_cookie(self, path):
        try:
            fis = FileInputStream(path)
            parts = []
            b = fis.read()
            while b != -1:
                parts.append("%02x" % (b & 0xFF))
                b = fis.read()
            fis.close()
            return "".join(parts)
        except:
            return None

    def signal_newnym(self):
        with self._lock:
            try:
                self._send("SIGNAL NEWNYM")
                resp = self.reader.readLine()
                return resp is not None and resp.startswith("250")
            except Exception as e:
                self.extender.log("NEWNYM error: " + str(e))
                return False

    def _send(self, cmd):
        data = JString(cmd + "\r\n").getBytes("UTF-8")
        self._out.write(data)
        self._out.flush()

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.sock = None
        self.reader = None
        self._out = None


# ---------------------------------------------------------------------------
# Background thread: rotate Tor circuit every ROTATION_INTERVAL seconds
# ---------------------------------------------------------------------------

class IPRotator(threading.Thread):

    def __init__(self, extender):
        threading.Thread.__init__(self)
        self.extender = extender
        self.daemon = True
        self._halt = threading.Event()

    def run(self):
        time.sleep(2)
        while not self._halt.is_set():
            ip = self._fetch_ip()
            if ip:
                self.extender.set_status(True, ip)
                self.extender.log("Exit IP: " + ip)
            else:
                self.extender.set_status(False)

            for i in range(ROTATION_INTERVAL):
                if self._halt.is_set():
                    return
                self.extender.update_countdown(ROTATION_INTERVAL - i)
                time.sleep(1)

            if not self._halt.is_set():
                if self.extender.tor_controller.signal_newnym():
                    self.extender.log("New circuit requested")
                    time.sleep(2)

    def _fetch_ip(self):
        try:
            px = Proxy(Proxy.Type.SOCKS,
                       InetSocketAddress("127.0.0.1", SOCKS_PORT))
            conn = URL(IP_CHECK_URL).openConnection(px)
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(10000)
            rdr = BufferedReader(InputStreamReader(conn.getInputStream()))
            ip = rdr.readLine()
            rdr.close()
            return ip.strip() if ip else None
        except:
            return None

    def stop_rotation(self):
        self._halt.set()


# ---------------------------------------------------------------------------
# Main Burp extension: wires everything together and builds the UI tab
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerExtensionStateListener(self)

        ext_file = callbacks.getExtensionFilename()
        ext_dir = File(ext_file).getParent() if ext_file else System.getProperty("user.dir")

        self.tor_manager = TorManager(self, ext_dir)
        self.tor_controller = TorController(self)
        self.rotator = None
        self._use_cookie = False

        self._log_area = None
        self._log_buf = []

        self._panel = JPanel(BorderLayout())
        SwingUtilities.invokeLater(self._build_ui)
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self._panel

    def extensionUnloaded(self):
        self._teardown()

    def _teardown(self):
        if self.rotator:
            self.rotator.stop_rotation()
            self.rotator = None
        self.tor_controller.close()
        self.tor_manager.stop()

    # -- Logging & status helpers ------------------------------------------------

    def log(self, msg):
        ts = time.strftime("%H:%M:%S")
        line = "[%s] %s\n" % (ts, msg)
        if self._log_area is None:
            self._log_buf.append(line)
            return

        def _append():
            self._log_area.append(line)
            self._log_area.setCaretPosition(
                self._log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_append)

    def set_status(self, connected, ip=""):
        def _update():
            if connected:
                green = Color(0, 200, 0)
                self._dot.setForeground(green)
                self._stxt.setText("Connected")
                self._stxt.setForeground(green)
                self._iplbl.setText("Exit IP:  " + ip)
            else:
                red = Color(220, 50, 50)
                self._dot.setForeground(red)
                self._stxt.setText("Disconnected")
                self._stxt.setForeground(red)
                self._iplbl.setText("Exit IP:  --")
        SwingUtilities.invokeLater(_update)

    def update_countdown(self, secs):
        def _set():
            self._cdlbl.setText("Next rotation: %ds" % secs)
        SwingUtilities.invokeLater(_set)

    # -- Tor lifecycle callbacks -------------------------------------------------

    def on_tor_ready(self):
        self.log("Tor bootstrapped! Connecting control port...")
        if self.tor_controller.connect(use_cookie=self._use_cookie,
                                       data_dir=self.tor_manager.data_dir):
            self.rotator = IPRotator(self)
            self.rotator.start()

            def _ui():
                self._btn_start.setEnabled(False)
                self._btn_stop.setEnabled(True)
            SwingUtilities.invokeLater(_ui)
        else:
            self.log("Control port connection failed")
            self.set_status(False)

    def on_tor_stopped(self):
        if self.rotator:
            self.rotator.stop_rotation()
            self.rotator = None
        self.tor_controller.close()
        self.tor_manager.process = None
        self.set_status(False)

        def _ui():
            self._btn_start.setEnabled(True)
            self._btn_stop.setEnabled(False)
            self._cdlbl.setText("")
        SwingUtilities.invokeLater(_ui)

    # -- Swing UI ----------------------------------------------------------------

    def _build_ui(self):
        self._panel.setBorder(EmptyBorder(15, 15, 15, 15))

        body = JPanel()
        body.setLayout(BoxLayout(body, BoxLayout.Y_AXIS))

        # ---- Header ----
        hdr = JPanel(FlowLayout(FlowLayout.CENTER))
        title = JLabel("T O R X Y")
        title.setFont(Font("SansSerif", Font.BOLD, 28))
        hdr.add(title)
        body.add(hdr)

        sub_hdr = JPanel(FlowLayout(FlowLayout.CENTER))
        sub = JLabel("Tor Proxy Engine for Burp Suite")
        sub.setFont(Font("SansSerif", Font.PLAIN, 13))
        sub_hdr.add(sub)
        body.add(sub_hdr)

        body.add(Box.createVerticalStrut(12))

        # ---- Instructions ----
        instr_panel = JPanel(BorderLayout())
        instr_panel.setBorder(BorderFactory.createTitledBorder("Quick Setup"))
        instr = JTextArea(
            " 1.  Click [ Start Tor ] below\n"
            " 2.  In Burp:  Settings  >  Network  >  Connections"
            "  >  SOCKS Proxy\n"
            " 3.  Enable SOCKS proxy   |   Host: 127.0.0.1"
            "   |   Port: %d\n"
            " 4.  Done!  IP rotates every %d seconds automatically"
            % (SOCKS_PORT, ROTATION_INTERVAL))
        instr.setEditable(False)
        instr.setOpaque(False)
        instr.setFont(Font("SansSerif", Font.PLAIN, 13))
        instr.setBorder(EmptyBorder(8, 12, 8, 12))
        instr_panel.add(instr, BorderLayout.CENTER)
        body.add(instr_panel)

        body.add(Box.createVerticalStrut(10))

        # ---- Status ----
        stat_panel = JPanel(BorderLayout())
        stat_panel.setBorder(BorderFactory.createTitledBorder("Status"))

        stat_inner = JPanel()
        stat_inner.setLayout(BoxLayout(stat_inner, BoxLayout.Y_AXIS))
        stat_inner.setBorder(EmptyBorder(8, 12, 8, 12))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        self._dot = JLabel(u"\u25CF")
        self._dot.setFont(Font("SansSerif", Font.BOLD, 20))
        self._dot.setForeground(Color(220, 50, 50))
        row1.add(self._dot)

        self._stxt = JLabel("Disconnected")
        self._stxt.setFont(Font("SansSerif", Font.BOLD, 14))
        self._stxt.setForeground(Color(220, 50, 50))
        row1.add(self._stxt)
        stat_inner.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        self._iplbl = JLabel("Exit IP:  --")
        self._iplbl.setFont(Font("Monospaced", Font.PLAIN, 13))
        row2.add(self._iplbl)

        row2.add(Box.createHorizontalStrut(20))
        self._cdlbl = JLabel("")
        self._cdlbl.setFont(Font("SansSerif", Font.PLAIN, 12))
        row2.add(self._cdlbl)
        stat_inner.add(row2)

        stat_panel.add(stat_inner, BorderLayout.CENTER)
        body.add(stat_panel)

        body.add(Box.createVerticalStrut(10))

        # ---- Controls ----
        ctrl = JPanel(FlowLayout(FlowLayout.LEFT, 10, 5))
        ctrl.setBorder(BorderFactory.createTitledBorder("Controls"))

        self._btn_start = JButton("Start Tor",
                                  actionPerformed=self._click_start)
        self._btn_start.setFont(Font("SansSerif", Font.BOLD, 13))
        ctrl.add(self._btn_start)

        self._btn_stop = JButton("Stop Tor",
                                 actionPerformed=self._click_stop)
        self._btn_stop.setFont(Font("SansSerif", Font.BOLD, 13))
        self._btn_stop.setEnabled(False)
        ctrl.add(self._btn_stop)

        ctrl.add(Box.createHorizontalStrut(15))
        ctrl.add(JLabel("Tor path:"))
        self._pathf = JTextField(20)
        self._pathf.setFont(Font("Monospaced", Font.PLAIN, 12))
        ctrl.add(self._pathf)
        ctrl.add(JButton("Set", actionPerformed=self._click_set))

        body.add(ctrl)

        body.add(Box.createVerticalStrut(10))

        # ---- Log ----
        log_panel = JPanel(BorderLayout())
        log_panel.setBorder(BorderFactory.createTitledBorder("Log"))
        self._log_area = JTextArea(12, 60)
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        log_panel.add(JScrollPane(self._log_area), BorderLayout.CENTER)
        body.add(log_panel)

        for buffered in self._log_buf:
            self._log_area.append(buffered)
        self._log_buf = []

        self._panel.add(JScrollPane(body), BorderLayout.CENTER)

        # ---- Kick off Tor detection in background ----
        self.log("Torxy loaded")
        self.log("Searching for Tor binary...")

        def _detect():
            path = self.tor_manager.find_tor()
            if path:
                SwingUtilities.invokeLater(
                    lambda: self._pathf.setText(path))
            else:
                self.log("Run ./setup.sh from the Torxy folder to")
                self.log("download bundled Tor binaries, then reload.")
                self.log("Or set a custom Tor path above and click Set.")

        t = threading.Thread(target=_detect)
        t.daemon = True
        t.start()

    # -- Button handlers ---------------------------------------------------------

    def _click_start(self, event):
        self._btn_start.setEnabled(False)

        def _go():
            if not self.tor_manager.tor_binary:
                self.log("Set the Tor binary path first.")
                SwingUtilities.invokeLater(
                    lambda: self._btn_start.setEnabled(True))
                return
            if not self.tor_manager.start():
                SwingUtilities.invokeLater(
                    lambda: self._btn_start.setEnabled(True))

        t = threading.Thread(target=_go)
        t.daemon = True
        t.start()

    def _click_stop(self, event):
        self._btn_stop.setEnabled(False)

        def _go():
            self._teardown()
            self.set_status(False)

            def _done():
                self._btn_start.setEnabled(True)
                self._cdlbl.setText("")
            SwingUtilities.invokeLater(_done)

        t = threading.Thread(target=_go)
        t.daemon = True
        t.start()

    def _click_set(self, event):
        path = self._pathf.getText().strip()
        if path and File(path).exists():
            self.tor_manager.tor_binary = path
            self.log("Tor path set: " + path)
        else:
            self.log("Invalid path: " + path)
            JOptionPane.showMessageDialog(
                self._panel,
                "File not found: " + path,
                "Invalid Path",
                JOptionPane.ERROR_MESSAGE)
