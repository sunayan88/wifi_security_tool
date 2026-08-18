"""Security alerts and local-data privacy controls."""

import customtkinter as ctk

from config import COLOR_DANGEROUS, COLOR_SAFE
from database.db_manager import clear_activity_history, clear_trust_data, get_privacy_counts
from gui.ui_utils import (
    BUTTON_RADIUS,
    CARD_DARK_ALT,
    MUTED_TEXT,
    PAGE_PAD_X,
    add_empty_state,
    confirm_dialog,
    make_card,
)
from modules.alert_system import get_all_alerts, get_alert_color


FILTER_TYPES = {
    "All": None,
    "WiFi": "WIFI",
    "Devices": "DEVICE",
    "System": "SYSTEM",
}


class AlertsTab:
    def __init__(self, parent):
        self.parent = parent
        self._build_ui()
        self._load_alerts()

    def _build_ui(self):
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(2, weight=1)

        header = make_card(self.parent)
        header.grid(row=0, column=0, padx=PAGE_PAD_X, pady=(12, 8), sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header, text="Security Alerts", font=ctk.CTkFont(size=15, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=14, sticky="w")
        self.count_label = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=12), text_color=MUTED_TEXT
        )
        self.count_label.grid(row=0, column=1, padx=12, sticky="e")
        ctk.CTkButton(
            header,
            text="Refresh",
            width=96,
            height=32,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=12),
            command=self._load_alerts,
        ).grid(row=0, column=2, padx=(0, 20), pady=14)

        filter_row = ctk.CTkFrame(self.parent, fg_color="transparent")
        filter_row.grid(row=1, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        ctk.CTkLabel(
            filter_row, text="Show", font=ctk.CTkFont(size=12), text_color=MUTED_TEXT
        ).pack(side="left", padx=(2, 10))
        self.filter_var = ctk.StringVar(value="All")
        self.filter_control = ctk.CTkSegmentedButton(
            filter_row,
            values=list(FILTER_TYPES),
            variable=self.filter_var,
            height=32,
            corner_radius=BUTTON_RADIUS,
            command=lambda _value: self._load_alerts(),
        )
        self.filter_control.pack(side="left")

        self.scroll_frame = ctk.CTkScrollableFrame(
            self.parent, corner_radius=10, fg_color=("gray95", CARD_DARK_ALT)
        )
        self.scroll_frame.grid(row=2, column=0, padx=PAGE_PAD_X, pady=(0, 10), sticky="nsew")
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        privacy = make_card(self.parent)
        privacy.grid(row=3, column=0, padx=PAGE_PAD_X, pady=(0, 16), sticky="ew")
        privacy.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            privacy, text="Privacy & Local Data", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=18, pady=(12, 2), sticky="w")
        self.privacy_status = ctk.CTkLabel(
            privacy,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=MUTED_TEXT,
            wraplength=720,
            justify="left",
            anchor="w",
        )
        self.privacy_status.grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")
        ctk.CTkButton(
            privacy,
            text="Clear Activity History",
            width=155,
            height=36,
            corner_radius=BUTTON_RADIUS,
            command=self._confirm_clear_history,
        ).grid(row=0, column=1, rowspan=2, padx=6, pady=12)
        ctk.CTkButton(
            privacy,
            text="Reset Trust Data",
            width=140,
            height=36,
            corner_radius=BUTTON_RADIUS,
            fg_color=COLOR_DANGEROUS,
            hover_color="#c0392b",
            command=self._confirm_clear_trust,
        ).grid(row=0, column=2, rowspan=2, padx=(6, 18), pady=12)
        self._refresh_privacy_status()

    def _load_alerts(self):
        self._clear_list()
        alerts = get_all_alerts()
        selected_type = FILTER_TYPES.get(self.filter_var.get())
        if selected_type:
            alerts = [alert for alert in alerts if alert["type"] == selected_type]

        count = len(alerts)
        self.count_label.configure(text=f"{count} alert{'s' if count != 1 else ''}")
        if not alerts:
            add_empty_state(
                self.scroll_frame,
                "No alerts in this view",
                "Security warnings, device changes, and system events will appear here.",
            )
            return

        for index, alert in enumerate(alerts):
            self._add_alert_row(index, alert, get_alert_color(alert["type"]))

    def _add_alert_row(self, index, alert, color):
        background = ("gray94", "#29293a") if index % 2 == 0 else ("gray91", "#242434")
        row = ctk.CTkFrame(self.scroll_frame, corner_radius=BUTTON_RADIUS, fg_color=background)
        row.grid(row=index, column=0, padx=4, pady=3, sticky="ew")
        row.grid_columnconfigure(1, weight=1)
        ctk.CTkFrame(row, width=5, corner_radius=4, fg_color=color).grid(
            row=0, column=0, rowspan=2, padx=(8, 12), pady=8, sticky="ns"
        )
        ctk.CTkLabel(
            row,
            text=alert["type_label"],
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=color,
        ).grid(row=0, column=1, pady=(8, 2), sticky="w")
        ctk.CTkLabel(
            row,
            text=alert["message"],
            font=ctk.CTkFont(size=12),
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=1, column=1, pady=(0, 8), sticky="ew")
        ctk.CTkLabel(
            row, text=alert["time"], font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        ).grid(row=0, column=2, rowspan=2, padx=16, sticky="e")

    def _clear_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

    def _refresh_privacy_status(self):
        counts = get_privacy_counts()
        self.privacy_status.configure(
            text=(
                f"Stored locally: {counts['devices']} device observations, "
                f"{counts['wifi_scans']} WiFi scans, {counts['alerts']} alerts, "
                f"{counts['trusted_networks']} trusted WiFi identities, and "
                f"{counts['trusted_gateways']} approved gateways."
            ),
            text_color=MUTED_TEXT,
        )

    def _confirm_clear_history(self):
        confirm_dialog(
            self.parent,
            "Clear activity history?",
            "Deletes device observations, WiFi scans, and alerts. Accounts, labels, and trust approvals are preserved.",
            self._clear_history,
            confirm_text="Delete History",
            danger=True,
        )

    def _confirm_clear_trust(self):
        confirm_dialog(
            self.parent,
            "Reset trust data?",
            "Deletes approved WiFi BSSIDs and gateway baselines. You will need to approve them again.",
            self._clear_trust,
            confirm_text="Reset Trust",
            danger=True,
        )

    def _clear_history(self):
        counts = clear_activity_history()
        total = sum(counts.values())
        self._load_alerts()
        self._refresh_privacy_status()
        self.privacy_status.configure(
            text=f"Deleted {total} local activity records. Trust choices were preserved.",
            text_color=COLOR_SAFE,
        )

    def _clear_trust(self):
        counts = clear_trust_data()
        total = sum(counts.values())
        self._refresh_privacy_status()
        self.privacy_status.configure(
            text=f"Deleted {total} trust approvals. Activity history was preserved.",
            text_color=COLOR_SAFE,
        )
