# ─────────────────────────────────────────────
#  WiFi Security Tool — WiFi Analyzer Tab
# ─────────────────────────────────────────────

import customtkinter as ctk
import threading
import traceback
import subprocess
import ctypes
from collections import defaultdict
from modules.wifi_analyzer import run_wifi_scan, disconnect_wifi
from modules.speed_test    import run_speed_test
from modules.dns_check     import check_dns_integrity
from modules.portal_check  import check_portal
from modules.network_identity import check_network_identity
from database.db_manager   import add_trusted_bssid
from utils.helpers         import get_local_ip
from config import RISK_SAFE, RISK_RISKY, RISK_DANGEROUS, COLOR_SAFE, COLOR_RISKY, COLOR_DANGEROUS
from gui.ui_utils import (
    BUTTON_RADIUS,
    CARD_DARK_ALT,
    MUTED_TEXT,
    PAGE_PAD_X,
    TABLE_HEADER_DARK,
    add_empty_state,
    make_card,
)

RISK_COLORS = {RISK_SAFE: COLOR_SAFE, RISK_RISKY: COLOR_RISKY, RISK_DANGEROUS: COLOR_DANGEROUS}
RISK_ICONS  = {RISK_SAFE: "SAFE", RISK_RISKY: "RISKY", RISK_DANGEROUS: "DANGEROUS"}

TRUST_LABELS = {
    "trusted":  ("Known",    COLOR_SAFE),
    "new":      ("New",      "#888888"),
    "mismatch": ("Mismatch", COLOR_DANGEROUS),
    "unknown":  ("-",        "#666666"),
}


def is_running_as_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_signal(s):
    try:
        return int(str(s).replace("%", "").strip())
    except (TypeError, ValueError):
        return 0


def connect_to_wifi(ssid):
    try:
        r = subprocess.run(
            ["netsh", "wlan", "connect", f"name={ssid}"],
            capture_output=True, creationflags=0x08000000
        )
        out = r.stdout.decode("utf-8", errors="ignore")
        if "successfully" in out.lower():
            return True, f"Connected to '{ssid}' successfully."
        return False, f"Could not connect to '{ssid}'. Make sure the profile is saved on your system."
    except Exception as e:
        return False, str(e)


class WiFiTab:
    def __init__(self, parent):
        self.parent        = parent
        self.networks      = []
        self.current_ssid  = None
        self.current_bssid = None
        self._build_ui()

    def _build_ui(self):
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(4, weight=1)

        top = ctk.CTkFrame(self.parent, fg_color="transparent")
        top.grid(row=0, column=0, padx=PAGE_PAD_X, pady=(10, 6), sticky="ew")
        top.grid_columnconfigure(0, weight=1, uniform="top_cards")
        top.grid_columnconfigure(1, weight=1, uniform="top_cards")
        top.grid_rowconfigure(0, weight=1)

        # ── Current Network Card ──────────
        card = make_card(top)
        card.grid(row=0, column=0, padx=(0, 8), pady=0, sticky="nsew")
        card.grid_columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(
            card, text="Current Network",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, columnspan=3, padx=16, pady=(12, 6), sticky="w")

        self.risk_label = ctk.CTkLabel(
            card, text="NOT SCANNED",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="gray", corner_radius=BUTTON_RADIUS, padx=12, pady=5
        )
        self.risk_label.grid(row=0, column=3, padx=16, pady=(12, 6), sticky="e")

        self.info_labels = {}
        fields = [
            ("Network Name", "ssid",           1, 0),
            ("Security",     "authentication", 1, 2),
            ("Signal",       "signal",         2, 0),
            ("BSSID",        "bssid",          2, 2),
            ("Band",         "band",           3, 0),
            ("Channel",      "channel",        3, 2),
            ("Your IP",      "local_ip",       4, 0),
            ("Strength",     "security_strength", 4, 2),
            ("WPS",          "wps",            5, 0),
        ]
        for lbl, key, r, c in fields:
            ctk.CTkLabel(
                card, text=f"{lbl}:",
                font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
            ).grid(row=r, column=c, padx=(16, 4), pady=3, sticky="w")
            v = ctk.CTkLabel(card, text="-", font=ctk.CTkFont(size=12))
            v.grid(row=r, column=c+1, padx=(0, 12), pady=3, sticky="w")
            self.info_labels[key] = v

        # ── Trust Row ──────────────────
        trust_row = ctk.CTkFrame(card, fg_color="transparent")
        trust_row.grid(row=6, column=0, columnspan=4, padx=16, pady=(6, 8), sticky="ew")
        trust_row.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(
            trust_row, text="Router Identity:",
            font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        ).grid(row=0, column=0, sticky="w")

        self.trust_status_label = ctk.CTkLabel(
            trust_row, text="-",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.trust_status_label.grid(row=0, column=1, padx=(8, 0), sticky="w")

        self.trust_btn = ctk.CTkButton(
            trust_row, text="Trust This Network",
            width=150, height=30, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=11),
            command=self._trust_current_network
        )
        self.security_disconnect_btn = ctk.CTkButton(
            trust_row, text="Disconnect Now",
            width=130, height=30, corner_radius=BUTTON_RADIUS,
            fg_color=COLOR_DANGEROUS, hover_color="#c0392b",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._disconnect_now
        )

        # ── Reason Label ──────────────
        start_message = (
            "Press 'Scan Network' to begin."
            if is_running_as_admin()
            else "For complete Windows WiFi results, restart this app as Administrator."
        )
        self.reason_label = ctk.CTkLabel(
            card, text=start_message,
            font=ctk.CTkFont(size=12), text_color=MUTED_TEXT,
            wraplength=650, anchor="w", justify="left"
        )
        self.reason_label.grid(row=7, column=0, columnspan=4, padx=16, pady=(0, 12), sticky="ew")

        # ── Evil Twin Warning (hidden) ───
        self.twin_frame = ctk.CTkFrame(
            self.parent, corner_radius=BUTTON_RADIUS, fg_color=("#ffe0b2", "#3d2000")
        )
        self.twin_label = ctk.CTkLabel(
            self.twin_frame, text="",
            font=ctk.CTkFont(size=12), text_color="#ff9800",
            wraplength=900, justify="left"
        )
        self.twin_label.pack(padx=16, pady=10, anchor="w")

        # ── Mismatch Banner (hidden) ─────
        self.mismatch_frame = ctk.CTkFrame(
            self.parent, corner_radius=BUTTON_RADIUS, fg_color=("#ffdada", "#3d0f0f")
        )
        self.mismatch_label = ctk.CTkLabel(
            self.mismatch_frame, text="",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#ff5252",
            wraplength=900, justify="left"
        )
        self.mismatch_label.pack(padx=16, pady=10, anchor="w")

        # ── Network Diagnostics Card ─────
        diag = make_card(top)
        diag.grid(row=0, column=1, padx=(8, 0), pady=0, sticky="nsew")
        diag.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            diag, text="Network Diagnostics",
            font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=2, padx=16, pady=(12, 8), sticky="w")

        # Speed test
        self.speed_btn = ctk.CTkButton(
            diag, text="Speed Test",
            width=120, height=32, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_speed_test
        )
        self.speed_btn.grid(row=1, column=0, padx=(16, 10), pady=(0, 8), sticky="w")

        self.speed_result = ctk.CTkLabel(
            diag, text="Ping: -   Download: -",
            font=ctk.CTkFont(size=12), text_color=MUTED_TEXT, anchor="w"
        )
        self.speed_result.grid(row=1, column=1, padx=(0, 16), pady=(0, 8), sticky="w")

        # DNS check
        self.dns_btn = ctk.CTkButton(
            diag, text="DNS / DoH",
            width=120, height=32, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_dns_check
        )
        self.dns_btn.grid(row=2, column=0, padx=(16, 10), pady=(0, 8), sticky="w")

        self.dns_result = ctk.CTkLabel(
            diag, text="DNS / DoH: -",
            font=ctk.CTkFont(size=12), text_color=MUTED_TEXT, anchor="w"
        )
        self.dns_result.grid(row=2, column=1, padx=(0, 16), pady=(0, 8), sticky="w")

        # Portal check
        self.portal_btn = ctk.CTkButton(
            diag, text="Portal Check",
            width=120, height=32, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_portal_check
        )
        self.portal_btn.grid(row=3, column=0, padx=(16, 10), pady=(0, 8), sticky="w")

        self.portal_result = ctk.CTkLabel(
            diag, text="Internet: -",
            font=ctk.CTkFont(size=12), text_color=MUTED_TEXT, anchor="w"
        )
        self.portal_result.grid(row=3, column=1, padx=(0, 16), pady=(0, 8), sticky="w")

        # Public network identity check
        self.identity_btn = ctk.CTkButton(
            diag, text="Identity Check",
            width=120, height=32, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_identity_check
        )
        self.identity_btn.grid(row=4, column=0, padx=(16, 10), pady=(0, 12), sticky="w")

        self.identity_result = ctk.CTkLabel(
            diag, text="Public IP / ISP: -",
            font=ctk.CTkFont(size=12), text_color=MUTED_TEXT,
            anchor="w", wraplength=860, justify="left"
        )
        self.identity_result.grid(
            row=4, column=1, padx=(0, 16), pady=(0, 12), sticky="ew"
        )

        # DNS detail box (hidden until check runs)
        self.dns_detail_frame = ctk.CTkFrame(
            self.parent, corner_radius=BUTTON_RADIUS,
            fg_color=("#fff8e1", "#2a2000")
        )
        self.dns_detail_label = ctk.CTkLabel(
            self.dns_detail_frame, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#f39c12", wraplength=900, justify="left"
        )
        self.dns_detail_label.pack(padx=14, pady=8, anchor="w")

        # ── Nearby Networks ─────────────
        nearby = make_card(self.parent)
        nearby.grid(row=4, column=0, padx=PAGE_PAD_X, pady=(0, 6), sticky="nsew")
        nearby.grid_columnconfigure(0, weight=1)
        nearby.grid_rowconfigure(2, weight=1)

        top_bar = ctk.CTkFrame(nearby, fg_color="transparent")
        top_bar.grid(row=0, column=0, padx=14, pady=(10, 5), sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top_bar, text="Nearby Networks",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, sticky="w")

        self.network_count = ctk.CTkLabel(
            top_bar, text="",
            font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        )
        self.network_count.grid(row=0, column=1, sticky="e")

        COLS = [("Signal", 55), ("SSID", 145), ("BSSID", 125), ("Band", 55),
                ("Security", 105), ("Strength", 70), ("WPS", 70),
                ("Trust", 75), ("Status", 85), ("", 70)]
        hdr = ctk.CTkFrame(nearby, fg_color=("#c8c8d8", TABLE_HEADER_DARK), corner_radius=6)
        hdr.grid(row=1, column=0, padx=14, pady=(0, 3), sticky="ew")
        for i, (txt, w) in enumerate(COLS):
            ctk.CTkLabel(
                hdr, text=txt,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=MUTED_TEXT, width=w, anchor="w"
            ).grid(row=0, column=i, padx=5, pady=7, sticky="w")

        self.net_scroll = ctk.CTkScrollableFrame(nearby, corner_radius=8, fg_color=("gray95", CARD_DARK_ALT))
        self.net_scroll.grid(row=2, column=0, padx=14, pady=(0, 10), sticky="nsew")
        self.net_scroll.grid_columnconfigure(0, weight=1)

        # ── Status + Buttons ──────────────
        self.connect_label = ctk.CTkLabel(
            self.parent, text="",
            font=ctk.CTkFont(size=12), text_color=COLOR_SAFE
        )
        self.connect_label.grid(row=5, column=0, padx=20, pady=(2, 2), sticky="w")

        btn_row = ctk.CTkFrame(self.parent, fg_color="transparent")
        btn_row.grid(row=6, column=0, padx=PAGE_PAD_X, pady=(2, 12), sticky="ew")
        btn_row.grid_columnconfigure(0, weight=3)
        btn_row.grid_columnconfigure(1, weight=1)

        self.scan_btn = ctk.CTkButton(
            btn_row, text="Scan WiFi Networks",
            height=40, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._start_scan
        )
        self.scan_btn.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.disconnect_btn = ctk.CTkButton(
            btn_row, text="Disconnect",
            height=40, corner_radius=BUTTON_RADIUS,
            fg_color=("#999999", "#444455"), hover_color=("#888888", "#555566"),
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self._disconnect_now
        )
        self.disconnect_btn.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        add_empty_state(
            self.net_scroll,
            "No WiFi scan yet",
            "Run a scan to compare nearby networks, encryption, WPS indicators, and router trust status.",
        )

    # ─── Scan ─────────────────────────────

    def _start_scan(self):
        self.scan_btn.configure(text="Scanning WiFi...", state="disabled")
        self.reason_label.configure(text="Reading the current connection and nearby networks...", text_color=MUTED_TEXT)
        self.connect_label.configure(text="")
        self._clear_networks()
        add_empty_state(self.net_scroll, "Scanning WiFi", "Windows is collecting nearby network details.")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            result = run_wifi_scan()
            self.parent.after(0, lambda: self._update_ui(result))
        except Exception as e:
            tb = traceback.format_exc()
            self.parent.after(0, lambda: self._show_error(str(e), tb))

    def _show_error(self, msg, tb):
        self.reason_label.configure(text=f"Error: {msg}", text_color=COLOR_DANGEROUS)
        self.scan_btn.configure(text="Scan WiFi Networks", state="normal")
        print(tb)

    def _update_ui(self, result):
        net          = result["network"]
        risk         = result["risk"]
        nearby       = result["nearby"]
        nearby_error = result.get("nearby_error")
        trust_status = result["trust_status"]

        self.current_ssid  = net.get("ssid", "Unknown")
        self.current_bssid = net.get("bssid", "Unknown")

        for key, lbl in self.info_labels.items():
            if key == "local_ip":
                lbl.configure(text=get_local_ip() or "Unknown")
            else:
                lbl.configure(text=net.get(key, "Unknown"))

        color = RISK_COLORS.get(risk, "gray")
        self.risk_label.configure(text=RISK_ICONS.get(risk, risk), fg_color=color)
        self.reason_label.configure(text=result["reason"], text_color=color)

        label, tcolor = TRUST_LABELS.get(trust_status, ("—", "#666666"))
        self.trust_status_label.configure(text=label, text_color=tcolor)

        self.trust_btn.grid_forget()
        self.security_disconnect_btn.grid_forget()
        if trust_status == "new":
            self.trust_btn.configure(text="Trust This Network")
            self.trust_btn.grid(row=0, column=2, padx=(12, 0), sticky="w")
        elif trust_status == "mismatch":
            self.trust_btn.configure(text="Trust Anyway (Router Changed)")
            self.trust_btn.grid(row=0, column=2, padx=(12, 0), sticky="w")
            self.security_disconnect_btn.grid(row=0, column=3, padx=(8, 0), sticky="w")

        if trust_status == "mismatch":
            self.mismatch_label.configure(
                text=(f"ROUTER IDENTITY MISMATCH\n"
                      f"'{self.current_ssid}' is being broadcast by a router we don't recognize "
                      f"({self.current_bssid}). If you didn't recently change your router, "
                      f"this could be a fake network designed to steal your data.")
            )
            self.mismatch_frame.grid(row=2, column=0, padx=16, pady=(0, 4), sticky="ew")
        else:
            self.mismatch_frame.grid_forget()

        sorted_nets = sorted(nearby, key=lambda n: parse_signal(n.get("signal", "0")), reverse=True)
        groups = defaultdict(list)
        for n in sorted_nets:
            groups[n["ssid"]].append(n)

        twin_ssids    = set()
        twin_messages = []
        for ssid, grp in groups.items():
            if len(grp) > 1:
                if any(g["is_open"] for g in grp) and any(not g["is_open"] for g in grp):
                    twin_ssids.add(ssid)
                    twin_messages.append(f"'{ssid}': open and secured variants detected")

        if twin_messages:
            self.twin_label.configure(
                text="Duplicate network names detected:\n" + "\n".join(twin_messages)
            )
            self.twin_frame.grid(row=3, column=0, padx=16, pady=(0, 4), sticky="ew")
        else:
            self.twin_frame.grid_forget()

        self._clear_networks()
        self.network_count.configure(text=f"{len(sorted_nets)} network(s) found")
        if not sorted_nets:
            message = nearby_error or "No nearby networks were returned by Windows."
            self._add_empty_network_message(message)
        else:
            for i, n in enumerate(sorted_nets):
                self._add_row(i, n, twin_ssids)

        self.scan_btn.configure(text="Scan WiFi Networks", state="normal")

    def _add_empty_network_message(self, message):
        add_empty_state(
            self.net_scroll,
            "No nearby networks displayed",
            (
                f"{message}\n\n"
                "Try enabling Windows Location services, then restart this app as Administrator."
            ),
        )

    def _add_row(self, idx, net, twin_ssids):
        ssid         = net["ssid"]
        sig          = parse_signal(net.get("signal", "0"))
        is_open      = net["is_open"]
        is_twin      = ssid in twin_ssids
        trust_status = net.get("trust_status", "unknown")
        band         = net.get("band", "Unknown")

        if trust_status == "mismatch":
            bg = ("#ffd6d6", "#400000")
        elif is_twin:
            bg = ("#fff3e0", "#2e1f00")
        elif is_open:
            bg = ("#fdecea", "#2e1010")
        elif idx % 2 == 0:
            bg = ("gray94", "#252535")
        else:
            bg = ("gray91", "#202030")

        row = ctk.CTkFrame(self.net_scroll, fg_color=bg, corner_radius=BUTTON_RADIUS)
        row.grid(row=idx, column=0, padx=2, pady=1, sticky="ew")
        self.net_scroll.grid_columnconfigure(0, weight=1)

        sig_color = COLOR_SAFE if sig >= 60 else COLOR_RISKY if sig >= 30 else "#888888"
        sig_frame = ctk.CTkFrame(row, fg_color="transparent", width=55)
        sig_frame.grid(row=0, column=0, padx=(10, 4), pady=8, sticky="w")
        sig_frame.grid_propagate(False)

        ctk.CTkLabel(
            sig_frame, text=f"{sig}%",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=sig_color, width=30, anchor="e"
        ).pack(side="left")

        bar = ctk.CTkProgressBar(sig_frame, width=20, height=7, corner_radius=3,
                                  fg_color=("gray75", "#333"), progress_color=sig_color)
        bar.pack(side="left", padx=(4, 0))
        bar.set(sig / 100)

        twin_tag = "  [duplicate]" if is_twin else ""
        ctk.CTkLabel(
            row, text=f"{ssid}{twin_tag}",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w", width=150
        ).grid(row=0, column=1, padx=5, pady=8, sticky="w")

        ctk.CTkLabel(
            row, text=net.get("bssid", "—"),
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=MUTED_TEXT, anchor="w", width=130
        ).grid(row=0, column=2, padx=5, pady=8, sticky="w")

        band_color = "#3498db" if band == "5 GHz" else "#9b59b6" if band == "2.4 GHz" else "#666666"
        ctk.CTkLabel(
            row, text=band,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=band_color, width=55
        ).grid(row=0, column=3, padx=5, pady=8, sticky="w")

        ctk.CTkLabel(
            row, text=net.get("authentication", "Unknown"),
            font=ctk.CTkFont(size=11), anchor="w", width=105
        ).grid(row=0, column=4, padx=5, pady=8, sticky="w")

        strength = net.get("security_strength", "Unknown")
        strength_color = (
            COLOR_DANGEROUS if strength == "Dangerous"
            else COLOR_RISKY if strength in {"Risky", "Unknown"}
            else COLOR_SAFE
        )
        ctk.CTkLabel(
            row, text=strength,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=strength_color, width=70
        ).grid(row=0, column=5, padx=5, pady=8, sticky="w")

        wps = net.get("wps", "Unknown")
        wps_color = COLOR_RISKY if "Enabled" in wps or "Mentioned" in wps else "#888888"
        ctk.CTkLabel(
            row, text=wps,
            font=ctk.CTkFont(size=10),
            text_color=wps_color, width=70
        ).grid(row=0, column=6, padx=5, pady=8, sticky="w")

        ttxt, tcol = TRUST_LABELS.get(trust_status, ("—", "#666666"))
        ctk.CTkLabel(
            row, text=ttxt,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=tcol, width=75
        ).grid(row=0, column=7, padx=5, pady=8, sticky="w")

        if trust_status == "mismatch":
            stxt, scol = "MISMATCH", COLOR_DANGEROUS
        elif is_twin:
            stxt, scol = "DUPLICATE", "#f39c12"
        elif is_open:
            stxt, scol = "OPEN", COLOR_DANGEROUS
        else:
            stxt, scol = "SECURED", COLOR_SAFE

        ctk.CTkLabel(
            row, text=stxt,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=scol, width=85
        ).grid(row=0, column=8, padx=5, pady=8, sticky="w")

        ctk.CTkButton(
            row, text="Connect",
            width=64, height=26, corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=11),
            fg_color=("#3a7ebf", "#1f538d"), hover_color=("#2d6299", "#174070"),
            command=lambda s=ssid: self._connect(s)
        ).grid(row=0, column=9, padx=8, pady=6)

    # ─── Trust Actions ─────────────────────

    def _trust_current_network(self):
        if not self.current_ssid or self.current_ssid == "Unknown":
            return
        add_trusted_bssid(self.current_ssid, self.current_bssid)
        self.connect_label.configure(
            text=f"'{self.current_ssid}' router ({self.current_bssid}) marked as trusted.",
            text_color=COLOR_SAFE
        )
        self.trust_status_label.configure(text="Known", text_color=COLOR_SAFE)
        self.trust_btn.grid_forget()
        self.security_disconnect_btn.grid_forget()
        self.mismatch_frame.grid_forget()

    # ─── Disconnect ─────────────────────────

    def _disconnect_now(self):
        self.connect_label.configure(text="Disconnecting...", text_color=MUTED_TEXT)
        threading.Thread(target=self._do_disconnect, daemon=True).start()

    def _do_disconnect(self):
        ok, msg = disconnect_wifi()
        col = COLOR_SAFE if ok else COLOR_DANGEROUS
        self.parent.after(0, lambda: self.connect_label.configure(text=msg, text_color=col))

    # ─── Connect ─────────────────────────

    def _connect(self, ssid):
        self.connect_label.configure(text=f"Connecting to '{ssid}'...", text_color=MUTED_TEXT)
        threading.Thread(target=self._do_connect, args=(ssid,), daemon=True).start()

    def _do_connect(self, ssid):
        ok, msg = connect_to_wifi(ssid)
        col = COLOR_SAFE if ok else COLOR_DANGEROUS
        self.parent.after(0, lambda: self.connect_label.configure(text=msg, text_color=col))

    # ─── Speed Test ─────────────────────────

    def _start_speed_test(self):
        self.speed_btn.configure(text="Testing...", state="disabled")
        self.speed_result.configure(text="Running speed test...", text_color=MUTED_TEXT)
        threading.Thread(target=self._run_speed_test, daemon=True).start()

    def _run_speed_test(self):
        result = run_speed_test()
        self.parent.after(0, lambda: self._show_speed(result))

    def _show_speed(self, result):
        ping = result.get("ping_ms")
        down = result.get("download_mbps")

        ping_str = f"{ping} ms" if ping is not None else "failed"
        down_str = f"{down} Mbps" if down is not None else "failed"

        ping_col = (COLOR_SAFE if ping and ping < 80 else
                    COLOR_RISKY if ping and ping < 200 else COLOR_DANGEROUS)
        down_col = (COLOR_SAFE if down and down > 15 else
                    COLOR_RISKY if down and down > 5 else COLOR_DANGEROUS)

        # Use the worse of the two colors for the combined label
        worst_col = COLOR_DANGEROUS if COLOR_DANGEROUS in (ping_col, down_col) else \
                    COLOR_RISKY if COLOR_RISKY in (ping_col, down_col) else COLOR_SAFE

        self.speed_result.configure(
            text=f"Ping: {ping_str}   Download: {down_str}",
            text_color=worst_col
        )
        self.speed_btn.configure(text="Speed Test", state="normal")

    # ─── DNS Check ─────────────────────────

    def _start_dns_check(self):
        self.dns_btn.configure(text="Checking...", state="disabled")
        self.dns_result.configure(text="Checking DNS...", text_color=MUTED_TEXT)
        self.dns_detail_frame.grid_forget()
        threading.Thread(target=self._run_dns_check, daemon=True).start()

    def _run_dns_check(self):
        result = check_dns_integrity()
        self.parent.after(0, lambda: self._show_dns(result))

    def _show_dns(self, result):
        status = result["status"]

        if status == "consistent":
            self.dns_result.configure(text="DNS: Consistent", text_color=COLOR_SAFE)
            self.dns_detail_frame.grid_forget()

        elif status == "suspicious":
            self.dns_result.configure(text="DNS: Suspicious pattern", text_color=COLOR_DANGEROUS)
            details = "\n".join(
                f["message"] for f in result["details"] if f["status"] == "suspicious"
            )
            self.dns_detail_label.configure(
                text=f"DNS manipulation may be occurring (checked against DoH references, not definitive):\n{details}",
                text_color=COLOR_DANGEROUS
            )
            self.dns_detail_frame.configure(fg_color=("#ffdada", "#3d0f0f"))
            self.dns_detail_frame.grid(row=1, column=0, padx=16, pady=(0, 4), sticky="ew")

            # Save to alerts
            from database.db_manager import save_alert
            save_alert("WIFI", f"Suspicious DNS consistency result: {details}")

        elif status == "inconclusive":
            self.dns_result.configure(text="DNS: Inconclusive", text_color=COLOR_RISKY)
            details = "\n".join(
                f["message"] for f in result["details"]
                if f["status"] in {"suspicious", "inconclusive"}
            )
            self.dns_detail_label.configure(text=details, text_color=COLOR_RISKY)
            self.dns_detail_frame.configure(fg_color=("#fff8e1", "#2a2000"))
            self.dns_detail_frame.grid(row=1, column=0, padx=16, pady=(0, 4), sticky="ew")
        else:
            self.dns_result.configure(text="DNS: Unreachable", text_color=COLOR_RISKY)
            self.dns_detail_frame.grid_forget()

        self.dns_btn.configure(text="DNS / DoH", state="normal")

    # ─── Portal Check ─────────────────────────

    def _start_portal_check(self):
        self.portal_btn.configure(text="Checking...", state="disabled")
        self.portal_result.configure(text="Checking internet...", text_color=MUTED_TEXT)
        threading.Thread(target=self._run_portal_check, daemon=True).start()

    def _run_portal_check(self):
        result = check_portal()
        self.parent.after(0, lambda: self._show_portal(result))

    def _show_portal(self, result):
        status = result["status"]

        if status == "online":
            self.portal_result.configure(text="Internet: Online", text_color=COLOR_SAFE)
        elif status == "captive_portal":
            self.portal_result.configure(text="Internet: Captive portal detected", text_color=COLOR_RISKY)
            # Show detail in DNS detail frame (reuse for captive portal message too)
            self.dns_detail_label.configure(
                text=f"Captive portal detected\n{result['message']}",
                text_color=COLOR_RISKY
            )
            self.dns_detail_frame.configure(fg_color=("#fff8e1", "#2a2000"))
            self.dns_detail_frame.grid(row=1, column=0, padx=16, pady=(0, 4), sticky="ew")
        else:
            self.portal_result.configure(
                text=f"Internet: {result.get('message', 'Unreachable')}",
                text_color=COLOR_DANGEROUS
            )

        self.portal_btn.configure(text="Portal Check", state="normal")

    # ─── Network Identity Check ─────────────────────────

    def _start_identity_check(self):
        self.identity_btn.configure(text="Checking...", state="disabled")
        self.identity_result.configure(text="Checking network identity...", text_color=MUTED_TEXT)
        threading.Thread(target=self._run_identity_check, daemon=True).start()

    def _run_identity_check(self):
        result = check_network_identity()
        self.parent.after(0, lambda: self._show_identity(result))

    def _show_identity(self, result):
        status = result.get("status")

        if status == "ok":
            text = (
                f"Public IP: {result.get('public_ip', 'Unknown')}   |   "
                f"ISP/ASN: {result.get('isp', 'Unknown')} ({result.get('asn', 'Unknown')})   |   "
                f"Location: {result.get('location', 'Unknown')}"
            )
            self.identity_result.configure(text=text, text_color=COLOR_SAFE)

        else:
            message = result.get("message", "Network identity check failed.")
            self.identity_result.configure(text=message, text_color=COLOR_DANGEROUS)

        self.identity_btn.configure(text="Identity Check", state="normal")

    # ─────────────────────────────────────────────

    def _clear_networks(self):
        for w in self.net_scroll.winfo_children():
            w.destroy()
