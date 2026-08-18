"""Gateway identity monitor UI."""

import threading

import customtkinter as ctk

from config import COLOR_DANGEROUS, COLOR_RISKY, COLOR_SAFE
from database.db_manager import approve_gateway
from gui.ui_utils import BUTTON_RADIUS, CARD_DARK_ALT, MUTED_TEXT, PAGE_PAD_X, make_card
from modules.arp_monitor import ARPMonitor, check_arp_spoof


STATUS_CONFIG = {
    "safe": ("GATEWAY MATCHES", COLOR_SAFE),
    "spoofed": ("GATEWAY IDENTITY CHANGED", COLOR_DANGEROUS),
    "unreachable": ("GATEWAY UNREACHABLE", COLOR_RISKY),
    "idle": ("NOT MONITORING", "#6b7280"),
    "unapproved": ("APPROVAL REQUIRED", COLOR_RISKY),
}


class ARPTab:
    def __init__(self, parent):
        self.parent = parent
        self.monitor = None
        self.snapshot = None
        self._build_ui()

    def _build_ui(self):
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(3, weight=1)

        overview = make_card(self.parent)
        overview.grid(row=0, column=0, padx=PAGE_PAD_X, pady=(12, 8), sticky="ew")
        overview.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            overview, text="Gateway Identity Monitor", font=ctk.CTkFont(size=15, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(14, 4), sticky="w")
        ctk.CTkLabel(
            overview,
            text=(
                "Compares the current gateway IP and MAC address with a baseline you explicitly approve. "
                "A change is a warning to investigate; it is not proof of an attack."
            ),
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            wraplength=1050,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 14), sticky="w")

        details = make_card(self.parent)
        details.grid(row=1, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        details.grid_columnconfigure((1, 3), weight=1, uniform="gateway_values")
        ctk.CTkLabel(
            details, text="Gateway Details", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=4, padx=20, pady=(12, 8), sticky="w")

        self.info_labels = {}
        fields = (
            ("Gateway IP", "ip", 1, 0),
            ("Approved MAC", "mac", 1, 2),
            ("Current MAC", "curr_mac", 2, 0),
            ("Check interval", "interval", 2, 2),
        )
        for title, key, row, column in fields:
            ctk.CTkLabel(
                details, text=f"{title}:", font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
            ).grid(row=row, column=column, padx=(20, 6), pady=5, sticky="w")
            value = ctk.CTkLabel(details, text="-", font=ctk.CTkFont(size=12), anchor="w")
            value.grid(row=row, column=column + 1, padx=(0, 18), pady=5, sticky="ew")
            self.info_labels[key] = value
        ctk.CTkLabel(details, text="").grid(row=3, column=0, pady=2)

        status_card = make_card(self.parent)
        status_card.grid(row=2, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        status_card.grid_columnconfigure(1, weight=1)
        self.status_indicator = ctk.CTkFrame(
            status_card, width=6, height=58, corner_radius=3, fg_color="#6b7280"
        )
        self.status_indicator.grid(row=0, column=0, rowspan=2, padx=(16, 12), pady=12, sticky="ns")
        self.status_label = ctk.CTkLabel(
            status_card, text="NOT MONITORING", font=ctk.CTkFont(size=13, weight="bold"), anchor="w"
        )
        self.status_label.grid(row=0, column=1, padx=(0, 16), pady=(13, 2), sticky="ew")
        self.status_msg = ctk.CTkLabel(
            status_card,
            text="Start monitoring to compare the current gateway with an approved baseline.",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            wraplength=1000,
            justify="left",
            anchor="w",
        )
        self.status_msg.grid(row=1, column=1, padx=(0, 16), pady=(0, 13), sticky="ew")

        log_card = make_card(self.parent)
        log_card.grid(row=3, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="nsew")
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(
            log_card, text="Monitor Activity", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(12, 8), sticky="w")
        self.log_box = ctk.CTkTextbox(
            log_card,
            height=130,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("gray95", CARD_DARK_ALT),
            state="disabled",
        )
        self.log_box.grid(row=1, column=0, padx=20, pady=(0, 16), sticky="nsew")

        controls = make_card(self.parent)
        controls.grid(row=4, column=0, padx=PAGE_PAD_X, pady=(0, 16), sticky="ew")
        controls.grid_columnconfigure(3, weight=1)
        ctk.CTkLabel(
            controls, text="Check interval", font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        ).grid(row=0, column=0, padx=(16, 8), pady=12, sticky="w")
        self.interval_var = ctk.StringVar(value="30")
        self.interval_menu = ctk.CTkOptionMenu(
            controls, values=["15", "30", "60", "120"], variable=self.interval_var, width=90, height=36
        )
        self.interval_menu.grid(row=0, column=1, pady=12, sticky="w")
        ctk.CTkLabel(
            controls, text="seconds", font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        ).grid(row=0, column=2, padx=(6, 14), pady=12, sticky="w")

        self.approve_btn = ctk.CTkButton(
            controls,
            text="Approve Observed Gateway",
            width=170,
            height=36,
            corner_radius=BUTTON_RADIUS,
            fg_color=COLOR_RISKY,
            state="disabled",
            command=self._approve_observed_gateway,
        )
        self.approve_btn.grid(row=0, column=4, padx=5, pady=12, sticky="e")
        self.check_now_btn = ctk.CTkButton(
            controls,
            text="Check Now",
            width=105,
            height=36,
            corner_radius=BUTTON_RADIUS,
            state="disabled",
            command=self._check_now,
        )
        self.check_now_btn.grid(row=0, column=5, padx=5, pady=12, sticky="e")
        self.stop_btn = ctk.CTkButton(
            controls,
            text="Stop",
            width=85,
            height=36,
            corner_radius=BUTTON_RADIUS,
            fg_color=("#777777", "#44444d"),
            state="disabled",
            command=self._stop_monitor,
        )
        self.stop_btn.grid(row=0, column=6, padx=5, pady=12, sticky="e")
        self.start_btn = ctk.CTkButton(
            controls,
            text="Start Monitoring",
            width=145,
            height=36,
            corner_radius=BUTTON_RADIUS,
            fg_color=COLOR_SAFE,
            hover_color="#27ae60",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._start_monitor,
        )
        self.start_btn.grid(row=0, column=7, padx=(5, 16), pady=12, sticky="e")

    def _start_monitor(self):
        self.start_btn.configure(text="Starting...", state="disabled")
        self._log("Starting gateway monitor and detecting the current gateway...")
        threading.Thread(target=self._do_start, daemon=True).start()

    def _do_start(self):
        interval = int(self.interval_var.get())
        self.monitor = ARPMonitor(on_alert=self._on_spoof_detected, interval_seconds=interval)
        ok, message = self.monitor.start()
        self.parent.after(0, lambda: self._on_monitor_started(ok, message))

    def _on_monitor_started(self, ok, message):
        if ok:
            approved = self.monitor.get_snapshot()
            observed = self.monitor.get_observed_snapshot()
            self.snapshot = observed
            self.info_labels["ip"].configure(text=approved["ip"])
            self.info_labels["mac"].configure(text=approved["mac"])
            self.info_labels["curr_mac"].configure(text=observed["mac"])
            self.info_labels["interval"].configure(text=f"{self.interval_var.get()} seconds")
            self._set_status("safe" if observed["mac"].upper() == approved["mac"].upper() else "spoofed")
            self._log(
                f"Monitoring started. Approved: {approved['ip']} ({approved['mac']}); current: {observed['mac']}"
            )
            self.stop_btn.configure(state="normal")
            self.check_now_btn.configure(state="normal")
            self.interval_menu.configure(state="disabled")
            return

        observed = self.monitor.get_observed_snapshot()
        if observed:
            self.snapshot = observed
            self.info_labels["ip"].configure(text=observed["ip"])
            self.info_labels["curr_mac"].configure(text=observed["mac"])
            self.info_labels["mac"].configure(text="Not approved")
            self.info_labels["interval"].configure(text=f"{self.interval_var.get()} seconds")
            self._set_status("unapproved")
            self.approve_btn.configure(state="normal")
        else:
            self._set_status("unreachable")
        self._log(f"Could not start monitoring: {message}")
        self.start_btn.configure(text="Start Monitoring", state="normal")

    def _approve_observed_gateway(self):
        if not self.snapshot:
            return
        approve_gateway(self.snapshot["network"], self.snapshot["ip"], self.snapshot["mac"])
        self.info_labels["mac"].configure(text=self.snapshot["mac"])
        self.approve_btn.configure(state="disabled")
        self._log(
            f"Gateway approved for {self.snapshot['network']}: {self.snapshot['ip']} ({self.snapshot['mac']})"
        )
        self._set_status("idle")
        self.status_msg.configure(text="Gateway approved. Start monitoring to compare against this baseline.")

    def _stop_monitor(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        self._set_status("idle")
        self._log("Gateway monitor stopped.")
        self.start_btn.configure(text="Start Monitoring", state="normal")
        self.stop_btn.configure(state="disabled")
        self.check_now_btn.configure(state="disabled")
        self.interval_menu.configure(state="normal")
        self.approve_btn.configure(state="disabled")

    def _check_now(self):
        if not self.monitor:
            return
        self.check_now_btn.configure(text="Checking...", state="disabled")
        threading.Thread(target=self._do_check_now, daemon=True).start()

    def _do_check_now(self):
        result = check_arp_spoof(self.monitor.get_snapshot())
        self.parent.after(0, lambda: self._on_check_result(result))

    def _on_check_result(self, result):
        self._set_status(result["status"])
        self.info_labels["curr_mac"].configure(text=result.get("current_mac") or "Unknown")
        self._log(f"Manual check: {result['message']}")
        self.check_now_btn.configure(text="Check Now", state="normal")

    def _on_spoof_detected(self, result):
        self.parent.after(0, lambda: self._show_spoof_alert(result))

    def _show_spoof_alert(self, result):
        self._set_status("spoofed")
        self.info_labels["curr_mac"].configure(text=result.get("current_mac") or "Unknown")
        self._log(f"Gateway identity warning: {result['message']}")

    def _set_status(self, status):
        label, color = STATUS_CONFIG.get(status, STATUS_CONFIG["idle"])
        self.status_label.configure(text=label, text_color=color)
        self.status_indicator.configure(fg_color=color)
        self.status_msg.configure(text=self._status_description(status))

    @staticmethod
    def _status_description(status):
        return {
            "safe": "The current gateway matches your explicitly approved identity.",
            "spoofed": "The gateway identity changed. Verify the router before performing sensitive activity.",
            "unreachable": "The gateway cannot be reached. You may be disconnected from the network.",
            "idle": "Start monitoring to compare the current gateway with an approved baseline.",
            "unapproved": "Verify the displayed gateway IP and MAC address before approving this baseline.",
        }.get(status, "")

    def _log(self, message):
        from utils.helpers import timestamp

        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{timestamp()}]  {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
