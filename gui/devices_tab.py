"""Connected-device view with MAC-based identity and persistent labels."""

import threading
import traceback

import customtkinter as ctk

from config import COLOR_DANGEROUS, COLOR_SAFE
from database.db_manager import delete_device_label, get_all_device_labels, set_device_label
from gui.ui_utils import (
    BUTTON_RADIUS,
    CARD_DARK_ALT,
    MUTED_TEXT,
    PAGE_PAD_X,
    TABLE_HEADER_DARK,
    add_empty_state,
    center_window,
    make_card,
)
from modules.device_monitor import run_device_scan


COLUMNS = (
    ("Device / Current IP", 2),
    ("MAC Identity", 2),
    ("Hostname", 2),
    ("Type / Privacy", 2),
    ("Identity", 1),
    ("Actions", 2),
)


class DevicesTab:
    def __init__(self, parent):
        self.parent = parent
        self.devices = []
        self.labels = {}
        self._build_ui()

    def _build_ui(self):
        self.parent.grid_columnconfigure(0, weight=1)
        self.parent.grid_rowconfigure(3, weight=1)

        header = make_card(self.parent)
        header.grid(row=0, column=0, padx=PAGE_PAD_X, pady=(12, 8), sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header, text="Connected Devices", font=ctk.CTkFont(size=15, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=14, sticky="w")
        self.device_count = ctk.CTkLabel(
            header, text="Not scanned", font=ctk.CTkFont(size=12), text_color=MUTED_TEXT
        )
        self.device_count.grid(row=0, column=1, padx=20, sticky="e")

        self.alert_frame = ctk.CTkFrame(
            self.parent, corner_radius=BUTTON_RADIUS, fg_color=("#ffe5e5", "#3a1a1a")
        )
        self.alert_label = ctk.CTkLabel(
            self.alert_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=COLOR_DANGEROUS,
            wraplength=980,
            justify="left",
        )
        self.alert_label.pack(fill="x", padx=16, pady=10, anchor="w")

        columns = ctk.CTkFrame(
            self.parent, corner_radius=6, fg_color=("#d8d8df", TABLE_HEADER_DARK)
        )
        columns.grid(row=2, column=0, padx=PAGE_PAD_X, pady=(0, 4), sticky="ew")
        self._configure_columns(columns)
        for index, (title, _weight) in enumerate(COLUMNS):
            ctk.CTkLabel(
                columns,
                text=title,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=MUTED_TEXT,
                anchor="w",
            ).grid(row=0, column=index, padx=10, pady=8, sticky="ew")

        self.scroll_frame = ctk.CTkScrollableFrame(
            self.parent, corner_radius=10, fg_color=("gray95", CARD_DARK_ALT)
        )
        self.scroll_frame.grid(row=3, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="nsew")
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        self.status_label = ctk.CTkLabel(
            self.parent,
            text="Identity is based on MAC address; local IP addresses may change.",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
        )
        self.status_label.grid(row=4, column=0, padx=PAGE_PAD_X, pady=(0, 6), sticky="w")

        self.scan_btn = ctk.CTkButton(
            self.parent,
            text="Scan Connected Devices",
            height=42,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._start_scan,
        )
        self.scan_btn.grid(row=5, column=0, padx=PAGE_PAD_X, pady=(0, 16), sticky="ew")

        add_empty_state(
            self.scroll_frame,
            "No device scan yet",
            "Run a scan to list devices by MAC identity, current IP, hostname, and privacy status.",
        )

    @staticmethod
    def _configure_columns(container):
        for index, (_title, weight) in enumerate(COLUMNS):
            container.grid_columnconfigure(index, weight=weight, uniform="device_columns")

    def _start_scan(self):
        self.scan_btn.configure(text="Scanning devices...", state="disabled")
        self.device_count.configure(text="Scanning...")
        self.status_label.configure(text="Discovering devices on the current local network.")
        self._clear_list()
        add_empty_state(self.scroll_frame, "Scanning", "This may take a few seconds.")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        try:
            self.labels = get_all_device_labels()
            results = run_device_scan()
            self.parent.after(0, lambda: self._update_ui(results))
        except Exception as exc:
            trace = traceback.format_exc()
            self.parent.after(0, lambda: self._show_error(str(exc)))
            print(trace)

    def _show_error(self, message):
        self._clear_list()
        add_empty_state(
            self.scroll_frame,
            "Device scan failed",
            "Check that WiFi is connected, then try running the application as Administrator.",
        )
        self.status_label.configure(text=f"Scan failed: {message}", text_color=COLOR_DANGEROUS)
        self.device_count.configure(text="Scan failed", text_color=COLOR_DANGEROUS)
        self.scan_btn.configure(text="Scan Connected Devices", state="normal")

    def _update_ui(self, results):
        self._clear_list()
        self.devices = results
        new_devices = [device for device in results if device["is_new"]]

        if new_devices:
            macs = ", ".join(device["mac"] for device in new_devices[:4])
            suffix = "..." if len(new_devices) > 4 else ""
            self.alert_label.configure(
                text=f"New MAC identities detected ({len(new_devices)}): {macs}{suffix}"
            )
            self.alert_frame.grid(row=1, column=0, padx=PAGE_PAD_X, pady=(0, 8), sticky="ew")
        else:
            self.alert_frame.grid_forget()

        if not results:
            add_empty_state(
                self.scroll_frame,
                "No devices found",
                "Confirm that WiFi is connected. Administrator access can improve discovery on Windows.",
            )
            self.status_label.configure(text="No devices were returned by the local network scan.", text_color=MUTED_TEXT)
        else:
            network = results[0].get("network", "Unknown WiFi")
            self.status_label.configure(
                text=f"MAC address is the device identity; IP is its current local address. Network: {network}",
                text_color=MUTED_TEXT,
            )
            for index, device in enumerate(results):
                self._add_device_row(index, device)

        total = len(results)
        new_count = len(new_devices)
        self.device_count.configure(
            text=f"{total} device{'s' if total != 1 else ''} | {new_count} new",
            text_color=COLOR_DANGEROUS if new_count else COLOR_SAFE,
        )
        self.scan_btn.configure(text="Scan Connected Devices", state="normal")

    def _add_device_row(self, index, device):
        mac = device["mac"]
        is_new = device["is_new"]
        label = self.labels.get(mac.upper())
        background = ("#f7e9e9", "#342020") if is_new else (
            ("gray94", "#272738") if index % 2 == 0 else ("gray91", "#222231")
        )

        row = ctk.CTkFrame(self.scroll_frame, fg_color=background, corner_radius=6)
        row.grid(row=index, column=0, padx=3, pady=2, sticky="ew")
        self._configure_columns(row)

        display = f"{label}\n{device['ip']}" if label else device["ip"]
        ctk.CTkLabel(
            row,
            text=display,
            font=ctk.CTkFont(size=12, weight="bold" if label else "normal"),
            text_color="#f39c12" if label else ("#18181b", "#f4f4f5"),
            anchor="w",
        ).grid(row=0, column=0, padx=10, pady=8, sticky="ew")
        ctk.CTkLabel(
            row, text=mac, font=ctk.CTkFont(family="Consolas", size=11), text_color=MUTED_TEXT, anchor="w"
        ).grid(row=0, column=1, padx=10, pady=8, sticky="ew")
        ctk.CTkLabel(row, text=device["hostname"], font=ctk.CTkFont(size=12), anchor="w").grid(
            row=0, column=2, padx=10, pady=8, sticky="ew"
        )

        type_text = device["type"]
        if device.get("is_private_mac"):
            type_text = f"{type_text}\nPrivate MAC"
        ctk.CTkLabel(
            row, text=type_text, font=ctk.CTkFont(size=11), text_color=MUTED_TEXT, anchor="w"
        ).grid(row=0, column=3, padx=10, pady=8, sticky="ew")

        status_text = "Labeled" if label and not is_new else device["status"]
        ctk.CTkLabel(
            row,
            text=status_text,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=COLOR_DANGEROUS if is_new else COLOR_SAFE,
            anchor="w",
        ).grid(row=0, column=4, padx=10, pady=8, sticky="ew")

        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.grid(row=0, column=5, padx=8, pady=5, sticky="e")
        ctk.CTkButton(
            actions,
            text="Rename" if label else "Label",
            width=72,
            height=28,
            corner_radius=6,
            font=ctk.CTkFont(size=11),
            command=lambda selected_mac=mac: self._open_label_dialog(selected_mac),
        ).pack(side="left", padx=(0, 4))
        if label:
            ctk.CTkButton(
                actions,
                text="Remove",
                width=60,
                height=28,
                corner_radius=6,
                font=ctk.CTkFont(size=10),
                fg_color=("#aaaaaa", "#444455"),
                command=lambda selected_mac=mac: self._remove_label(selected_mac),
            ).pack(side="left")

    def _open_label_dialog(self, mac):
        dialog = ctk.CTkToplevel(self.parent)
        dialog.title("Label Device")
        dialog.resizable(False, False)
        dialog.transient(self.parent.winfo_toplevel())
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        center_window(dialog, 420, 235, self.parent.winfo_toplevel())
        dialog.grab_set()

        current = self.labels.get(mac.upper(), "")
        heading = ctk.CTkFrame(dialog, fg_color="transparent")
        heading.pack(fill="x", padx=20, pady=(14, 0))
        ctk.CTkLabel(
            heading, text="Name this device", font=ctk.CTkFont(size=15, weight="bold")
        ).pack(side="left")
        ctk.CTkButton(
            heading, text="X", width=32, height=30, fg_color="transparent", command=dialog.destroy
        ).pack(side="right")
        ctk.CTkLabel(
            dialog, text=f"MAC identity: {mac}", font=ctk.CTkFont(size=11), text_color=MUTED_TEXT
        ).pack(padx=20, pady=(4, 0), anchor="w")

        entry = ctk.CTkEntry(
            dialog, placeholder_text="Example: My Laptop", font=ctk.CTkFont(size=12), height=38
        )
        entry.pack(padx=20, pady=14, fill="x")
        if current:
            entry.insert(0, current)

        def save():
            value = entry.get().strip()
            if not value:
                return
            set_device_label(mac, value)
            self.labels[mac.upper()] = value
            dialog.destroy()
            self._refresh_list()

        ctk.CTkButton(
            dialog, text="Save Device Label", height=38, corner_radius=BUTTON_RADIUS, command=save
        ).pack(padx=20, pady=(0, 14), fill="x")
        entry.bind("<Return>", lambda _event: save())
        entry.focus_set()

    def _remove_label(self, mac):
        delete_device_label(mac)
        self.labels.pop(mac.upper(), None)
        self._refresh_list()

    def _refresh_list(self):
        self._clear_list()
        for index, device in enumerate(self.devices):
            self._add_device_row(index, device)

    def _clear_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
