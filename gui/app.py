import customtkinter as ctk

from config import APP_NAME, APP_VERSION, SCAN_INTERVAL_SECONDS
from gui.alerts_tab import AlertsTab
from gui.arp_tab import ARPTab
from gui.devices_tab import DevicesTab
from gui.disruption_tab import DisruptionTab
from gui.ui_utils import APP_BG, HEADER_BG, MUTED_TEXT, confirm_dialog
from gui.wifi_tab import WiFiTab


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App:
    def __init__(self, username="User"):
        self.username = username
        self.exit_action = "exit"

        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1360, max(1100, screen_w - 100))
        height = min(860, max(700, screen_h - 120))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(1100, 700)
        self.root.configure(fg_color=APP_BG)
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

        self._build_header()
        self._build_tabs()
        self._start_auto_refresh()

    def _build_header(self):
        header = ctk.CTkFrame(
            self.root,
            height=54,
            corner_radius=0,
            fg_color=("#e8e8e8", HEADER_BG),
        )
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text=APP_NAME,
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(side="left", padx=20)

        self.status_label = ctk.CTkLabel(
            header,
            text="● Monitoring",
            font=ctk.CTkFont(size=11),
            text_color="#2ecc71",
        )
        self.status_label.pack(side="right", padx=(8, 18))

        ctk.CTkButton(
            header,
            text="Log Out",
            width=80,
            height=32,
            fg_color="transparent",
            border_width=1,
            command=self._confirm_logout,
        ).pack(side="right", padx=6)

        self.scale_var = ctk.StringVar(value="100%")
        ctk.CTkOptionMenu(
            header,
            values=["80%", "90%", "100%", "110%", "125%"],
            variable=self.scale_var,
            width=82,
            height=32,
            command=self._change_scale,
        ).pack(side="right", padx=6)

        display_name = self.username if len(self.username) <= 24 else f"{self.username[:21]}..."
        ctk.CTkLabel(
            header,
            text=f"Welcome, {display_name}",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
        ).pack(side="right", padx=(8, 6))

    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(
            self.root,
            corner_radius=10,
            anchor="nw",
            fg_color=("#f2f2f2", "#242428"),
            segmented_button_fg_color=("#dddddd", "#3a3a3f"),
            segmented_button_selected_color=("#2f80c7", "#1f6aa5"),
            segmented_button_selected_hover_color=("#256ba6", "#185985"),
        )
        self.tabview.pack(fill="both", expand=True, padx=12, pady=12)

        self.tabview.add("WiFi Analyzer")
        self.wifi_tab = WiFiTab(self.tabview.tab("WiFi Analyzer"))
        self.tabview.add("Device Monitor")
        self.device_tab = DevicesTab(self.tabview.tab("Device Monitor"))
        self.tabview.add("Gateway Monitor")
        self.arp_tab = ARPTab(self.tabview.tab("Gateway Monitor"))
        self.tabview.add("Disruption Watch")
        self.disruption_tab = DisruptionTab(self.tabview.tab("Disruption Watch"))
        self.tabview.add("Alerts")
        self.alerts_tab = AlertsTab(self.tabview.tab("Alerts"))

    def _start_auto_refresh(self):
        """Auto-refresh the Alerts tab every SCAN_INTERVAL_SECONDS."""
        try:
            self.alerts_tab._load_alerts()
        except Exception:
            pass
        if self.root.winfo_exists():
            self.root.after(SCAN_INTERVAL_SECONDS * 1000, self._start_auto_refresh)

    def _change_scale(self, value):
        ctk.set_widget_scaling(int(value.rstrip("%")) / 100)

    def _stop_background_work(self):
        monitor = getattr(getattr(self, "arp_tab", None), "monitor", None)
        if monitor:
            monitor.stop()
        disruption = getattr(getattr(self, "disruption_tab", None), "monitor", None)
        if disruption:
            disruption.stop()

    def _confirm_logout(self):
        confirm_dialog(
            self.root,
            "Log out?",
            "Monitoring will stop and you will return to the sign-in screen.",
            self._logout,
            confirm_text="Log Out",
        )

    def _logout(self):
        self._stop_background_work()
        self.exit_action = "logout"
        self.root.destroy()

    def _close(self):
        self._stop_background_work()
        self.exit_action = "exit"
        self.root.destroy()

    def run(self):
        self.root.mainloop()
        return self.exit_action
