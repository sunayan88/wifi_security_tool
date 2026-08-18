import datetime
import customtkinter as ctk

from config import COLOR_DANGEROUS, COLOR_RISKY, COLOR_SAFE
from gui.ui_utils import BUTTON_RADIUS, CARD_DARK_ALT, MUTED_TEXT, PAGE_PAD_X, make_card
from modules.disruption_monitor import SymptomDisruptionMonitor


STATUS_COLORS = {
    "normal": COLOR_SAFE,
    "unstable": COLOR_RISKY,
    "suspicious": COLOR_RISKY,
    "high_risk": COLOR_DANGEROUS,
    "idle": "gray",
}


class DisruptionTab:
    def __init__(self, parent):
        self.parent = parent
        self.monitor = SymptomDisruptionMonitor(self._on_update)
        self._build_ui()

    def _build_ui(self):
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(3, weight=1)

        card = make_card(self.parent)
        card.grid(row=0, column=0, padx=PAGE_PAD_X, pady=(12, 8), sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card,
            text="WiFi Disruption Watch",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).grid(row=0, column=0, padx=18, pady=(14, 4), sticky="w")

        self.status_badge = ctk.CTkLabel(
            card,
            text="IDLE",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="gray",
            corner_radius=8,
            padx=12,
            pady=5,
        )
        self.status_badge.grid(row=0, column=1, padx=18, pady=(14, 4), sticky="e")

        ctk.CTkLabel(
            card,
            text=(
                "Windows-friendly monitor for unusual network symptoms: "
                "frequent disconnect/reconnect, same SSID with BSSID/gateway changes, "
                "and sudden signal drops. It warns about possible disruption; it does not "
                "claim packet-level proof of deauth/DoS."
            ),
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            wraplength=1000,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, padx=18, pady=(0, 12), sticky="w")

        controls = make_card(self.parent)
        controls.grid(row=1, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        controls.grid_columnconfigure(2, weight=1)

        self.start_btn = ctk.CTkButton(
            controls,
            text="Start Symptom Watch",
            height=36,
            corner_radius=BUTTON_RADIUS,
            command=self._start,
        )
        self.start_btn.grid(row=0, column=0, padx=14, pady=14, sticky="w")

        self.stop_btn = ctk.CTkButton(
            controls,
            text="Stop",
            height=36,
            corner_radius=BUTTON_RADIUS,
            state="disabled",
            fg_color=("#777", "#444"),
            command=self._stop,
        )
        self.stop_btn.grid(row=0, column=1, padx=8, pady=14, sticky="w")

        self.summary_label = ctk.CTkLabel(
            controls,
            text="Not running.",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            wraplength=950,
            justify="left",
        )
        self.summary_label.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 14), sticky="w")

        metrics = make_card(self.parent)
        metrics.grid(row=2, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        metrics.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.metric_labels = {}
        for i, key in enumerate(["disconnects", "reconnects", "bssid_changes", "gateway_changes", "signal_drops"]):
            box = ctk.CTkFrame(metrics, corner_radius=10)
            box.grid(row=0, column=i, padx=8, pady=12, sticky="ew")
            ctk.CTkLabel(
                box,
                text=key.replace("_", " ").title(),
                font=ctk.CTkFont(size=11),
                text_color=MUTED_TEXT,
            ).pack(pady=(10, 2))
            label = ctk.CTkLabel(box, text="0", font=ctk.CTkFont(size=18, weight="bold"))
            label.pack(pady=(0, 10))
            self.metric_labels[key] = label

        self.events_frame = ctk.CTkScrollableFrame(
            self.parent,
            corner_radius=12,
            fg_color=("gray95", CARD_DARK_ALT),
        )
        self.events_frame.grid(row=3, column=0, padx=PAGE_PAD_X, pady=(0, 16), sticky="nsew")
        self.events_frame.grid_columnconfigure(0, weight=1)

        self._render_events([])

    def _start(self):
        ok, msg = self.monitor.start()
        self.summary_label.configure(text=msg, text_color=COLOR_SAFE if ok else COLOR_RISKY)
        if ok:
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self._set_status("normal")

    def _stop(self):
        self.monitor.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.summary_label.configure(text="Symptom watch stopped.", text_color=MUTED_TEXT)
        self._set_status("idle")

    def _on_update(self, snapshot):
        self.parent.after(0, lambda: self._show_snapshot(snapshot))

    def _show_snapshot(self, snapshot):
        self._set_status(snapshot["status"])
        self.summary_label.configure(
            text=f"Score: {snapshot['score']} | {snapshot['message']}",
            text_color=STATUS_COLORS.get(snapshot["status"], "gray"),
        )
        for key, label in self.metric_labels.items():
            label.configure(text=str(snapshot.get(key, 0)))
        self._render_events(snapshot["recent"])

    def _set_status(self, status):
        label = {
            "idle": "IDLE",
            "normal": "NORMAL",
            "unstable": "UNSTABLE",
            "suspicious": "SUSPICIOUS",
            "high_risk": "HIGH RISK",
        }.get(status, status.upper())
        self.status_badge.configure(
            text=label,
            fg_color=STATUS_COLORS.get(status, "gray"),
        )

    def _render_events(self, events):
        for widget in self.events_frame.winfo_children():
            widget.destroy()

        if not events:
            ctk.CTkLabel(
                self.events_frame,
                text="No unusual WiFi symptoms observed yet.",
                font=ctk.CTkFont(size=13),
                text_color=MUTED_TEXT,
            ).grid(row=0, column=0, padx=16, pady=20)
            return

        for i, event in enumerate(reversed(events)):
            ts = datetime.datetime.fromtimestamp(event["time"]).strftime("%H:%M:%S")
            row = ctk.CTkFrame(self.events_frame, corner_radius=8)
            row.grid(row=i, column=0, padx=8, pady=4, sticky="ew")
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                row,
                text=ts,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=MUTED_TEXT,
            ).grid(row=0, column=0, padx=12, pady=8, sticky="w")
            ctk.CTkLabel(
                row,
                text=f"{event['kind'].replace('_', ' ').title()}: {event['message']}",
                font=ctk.CTkFont(size=12),
                text_color=COLOR_RISKY,
                anchor="w",
                wraplength=900,
            ).grid(row=0, column=1, padx=12, pady=8, sticky="w")
