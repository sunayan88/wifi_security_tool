import customtkinter as ctk

APP_BG = "#1b1b1f"
HEADER_BG = "#11111b"
CARD_DARK = "#252535"
CARD_DARK_ALT = "#202030"
TABLE_HEADER_DARK = "#1e1e30"
MUTED_TEXT = "#9ca3af"
SOFT_BORDER = "#343445"
PRIMARY_BLUE = "#1f6aa5"
PRIMARY_BLUE_HOVER = "#185985"
SECONDARY_DARK = "#34343f"
SECONDARY_DARK_HOVER = "#41414e"

PAGE_PAD_X = 16
PAGE_PAD_Y = 12
CARD_RADIUS = 12
BUTTON_RADIUS = 8


def style_secondary_button(button):
    """Apply the shared low-emphasis button style."""
    button.configure(
        fg_color=("#d6d6dc", SECONDARY_DARK),
        hover_color=("#c7c7cf", SECONDARY_DARK_HOVER),
        text_color=("#18181b", "#f4f4f5"),
        corner_radius=BUTTON_RADIUS,
    )
    return button


def center_window(window, width, height, parent=None):
    """Size and center a window inside the visible screen."""
    window.update_idletasks()
    if parent is not None and parent.winfo_exists():
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
    else:
        x = max(0, (window.winfo_screenwidth() - width) // 2)
        y = max(0, (window.winfo_screenheight() - height) // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")


def confirm_dialog(parent, title, message, on_confirm, confirm_text="Confirm",
                   danger=False):
    """Show a keyboard-friendly modal with visible Cancel and close controls."""
    top = parent.winfo_toplevel()
    dialog = ctk.CTkToplevel(top)
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.transient(top)

    header = ctk.CTkFrame(dialog, fg_color="transparent")
    header.pack(fill="x", padx=20, pady=(16, 4))
    ctk.CTkLabel(
        header, text=title, font=ctk.CTkFont(size=16, weight="bold")
    ).pack(side="left")
    ctk.CTkButton(
        header, text="X", width=32, height=30,
        fg_color="transparent", hover_color=("#dddddd", "#333344"),
        command=dialog.destroy,
    ).pack(side="right")
    ctk.CTkLabel(
        dialog, text=message, wraplength=390, justify="left",
        anchor="w", text_color="gray",
    ).pack(fill="x", padx=22, pady=(8, 20))

    buttons = ctk.CTkFrame(dialog, fg_color="transparent")
    buttons.pack(fill="x", padx=20, pady=(0, 18))

    def confirm():
        dialog.destroy()
        on_confirm()

    ctk.CTkButton(
        buttons, text="Cancel", width=110, command=dialog.destroy,
        fg_color=("#d6d6dc", SECONDARY_DARK),
        hover_color=("#c7c7cf", SECONDARY_DARK_HOVER),
        text_color=("#18181b", "#f4f4f5"),
        corner_radius=BUTTON_RADIUS,
    ).pack(side="right", padx=(8, 0))
    confirm_options = {"fg_color": "#e74c3c", "hover_color": "#c0392b"} if danger else {}
    ctk.CTkButton(
        buttons, text=confirm_text, width=130, command=confirm,
        corner_radius=BUTTON_RADIUS,
        **confirm_options,
    ).pack(side="right")

    dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    dialog.bind("<Escape>", lambda _event: dialog.destroy())
    dialog.bind("<Return>", lambda _event: confirm())
    center_window(dialog, 460, 215, top)
    dialog.grab_set()
    dialog.focus_force()
    return dialog


def make_card(parent, **grid_options):
    """Create a standard dark rounded card and optionally grid it."""
    card = ctk.CTkFrame(
        parent,
        corner_radius=CARD_RADIUS,
        fg_color=("gray95", CARD_DARK),
        border_width=1,
        border_color=("gray80", SOFT_BORDER),
    )
    if grid_options:
        card.grid(**grid_options)
    return card


def add_empty_state(parent, title, message, row=0):
    """Render a quiet empty state inside a list/table area."""
    box = ctk.CTkFrame(
        parent,
        corner_radius=10,
        fg_color=("gray94", CARD_DARK_ALT),
    )
    box.grid(row=row, column=0, padx=6, pady=8, sticky="ew")
    box.grid_columnconfigure(0, weight=1)

    ctk.CTkLabel(
        box,
        text=title,
        font=ctk.CTkFont(size=13, weight="bold"),
        text_color=MUTED_TEXT,
    ).grid(row=0, column=0, padx=16, pady=(14, 2), sticky="w")

    ctk.CTkLabel(
        box,
        text=message,
        font=ctk.CTkFont(size=12),
        text_color=MUTED_TEXT,
        wraplength=860,
        justify="left",
        anchor="w",
    ).grid(row=1, column=0, padx=16, pady=(0, 14), sticky="ew")

    return box
