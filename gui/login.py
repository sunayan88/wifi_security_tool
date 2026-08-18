import customtkinter as ctk

from config import APP_NAME, COLOR_DANGEROUS, COLOR_SAFE
from database.db_manager import login_user, register_user
from gui.ui_utils import BUTTON_RADIUS, MUTED_TEXT, center_window, make_card


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class LoginWindow:
    def __init__(self, on_success=None):
        self.on_success = on_success
        self.is_signup = False
        self.authenticated_username = None

        self.root = ctk.CTk()
        self.root.title(f"{APP_NAME} - Login")
        self.root.minsize(400, 520)
        self.root.resizable(True, True)
        center_window(self.root, 460, 600)

        self._build_ui()

    def _build_ui(self):
        self.root.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.root,
            text=APP_NAME,
            font=ctk.CTkFont(size=20, weight="bold"),
        ).grid(row=0, column=0, pady=(40, 4), padx=40)

        ctk.CTkLabel(
            self.root,
            text="Kathmandu Valley Network Safety Tool",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
        ).grid(row=1, column=0, pady=(0, 24), padx=40)

        self.card = make_card(self.root)
        self.card.grid(row=2, column=0, padx=36, sticky="ew")
        self.card.grid_columnconfigure(0, weight=1)

        self.form_title = ctk.CTkLabel(
            self.card,
            text="Sign In",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w",
        )
        self.form_title.grid(row=0, column=0, padx=24, pady=(24, 16), sticky="w")

        ctk.CTkLabel(
            self.card,
            text="Username",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            anchor="w",
        ).grid(row=1, column=0, padx=24, sticky="w")

        self.username_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Enter your username",
            height=40,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=13),
        )
        self.username_entry.grid(row=2, column=0, padx=24, pady=(4, 14), sticky="ew")

        ctk.CTkLabel(
            self.card,
            text="Password",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            anchor="w",
        ).grid(row=3, column=0, padx=24, sticky="w")

        self.password_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Enter your password",
            show="*",
            height=40,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=13),
        )
        self.password_entry.grid(row=4, column=0, padx=24, pady=(4, 14), sticky="ew")

        self.confirm_label = ctk.CTkLabel(
            self.card,
            text="Confirm Password",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
            anchor="w",
        )
        self.confirm_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Repeat your password",
            show="*",
            height=40,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=13),
        )

        self.status_label = ctk.CTkLabel(
            self.card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=COLOR_DANGEROUS,
            wraplength=340,
        )
        self.status_label.grid(row=7, column=0, padx=24, pady=(0, 8), sticky="w")

        self.submit_btn = ctk.CTkButton(
            self.card,
            text="Sign In",
            height=42,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLOR_SAFE,
            hover_color="#27ae60",
            command=self._handle_submit,
        )
        self.submit_btn.grid(row=8, column=0, padx=24, pady=(0, 24), sticky="ew")

        self.guest_btn = ctk.CTkButton(
            self.card,
            text="Continue as Guest",
            height=38,
            corner_radius=BUTTON_RADIUS,
            font=ctk.CTkFont(size=13),
            fg_color="transparent",
            border_width=1,
            command=self._continue_as_guest,
        )
        self.guest_btn.grid(row=9, column=0, padx=24, pady=(0, 20), sticky="ew")

        toggle_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        toggle_frame.grid(row=3, column=0, pady=16)

        self.toggle_prompt = ctk.CTkLabel(
            toggle_frame,
            text="Don't have an account? ",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
        )
        self.toggle_prompt.grid(row=0, column=0)

        self.toggle_btn = ctk.CTkLabel(
            toggle_frame,
            text="Sign Up",
            font=ctk.CTkFont(size=12, underline=True),
            text_color="#7c9ef5",
            cursor="hand2",
        )
        self.toggle_btn.grid(row=0, column=1)
        self.toggle_btn.bind("<Button-1>", lambda _event: self._toggle_mode())

        self.toggle_hint = ctk.CTkLabel(
            toggle_frame,
            text="",
            font=ctk.CTkFont(size=12),
            text_color=MUTED_TEXT,
        )
        self.toggle_hint.grid(row=0, column=2)

        self.back_btn = ctk.CTkButton(
            self.root,
            text="Back to Sign In",
            width=150,
            fg_color="transparent",
            border_width=1,
            command=lambda: self._set_mode(False),
        )

        self.root.bind("<Return>", lambda _event: self._handle_submit())

    def _toggle_mode(self):
        self._set_mode(not self.is_signup)

    def _set_mode(self, signup):
        self.is_signup = signup
        self.status_label.configure(text="")

        if self.is_signup:
            self.form_title.configure(text="Create Account")
            self.submit_btn.configure(text="Sign Up")
            self.guest_btn.grid_forget()
            self.toggle_prompt.configure(text="Already have an account? ")
            self.toggle_btn.configure(text="Sign In")
            self.toggle_hint.configure(text="")
            self.confirm_label.grid(row=5, column=0, padx=24, sticky="w")
            self.confirm_entry.grid(row=6, column=0, padx=24, pady=(4, 14), sticky="ew")
            self.back_btn.grid(row=4, column=0, pady=(0, 16))
            self.confirm_entry.focus_set()
        else:
            self.form_title.configure(text="Sign In")
            self.submit_btn.configure(text="Sign In")
            self.guest_btn.grid(row=9, column=0, padx=24, pady=(0, 20), sticky="ew")
            self.toggle_prompt.configure(text="Don't have an account? ")
            self.toggle_btn.configure(text="Sign Up")
            self.confirm_label.grid_forget()
            self.confirm_entry.grid_forget()
            self.back_btn.grid_forget()
            self.confirm_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
            self.username_entry.focus_set()

    def _handle_submit(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if self.is_signup:
            confirm = self.confirm_entry.get().strip()
            if password != confirm:
                self._show_error("Passwords do not match.")
                return
            success, message = register_user(username, password)
            if success:
                self._set_mode(False)
                self._show_success(f"{message} You can now sign in.")
            else:
                self._show_error(message)
        else:
            success, result = login_user(username, password)
            if success:
                _uid, uname = result
                self.root.withdraw()
                self.root.after(200, lambda: self._finish_login(uname))
            else:
                self._show_error(result)

    def _continue_as_guest(self):
        self.root.withdraw()
        self.root.after(200, lambda: self._finish_login("Guest"))

    def _show_error(self, msg):
        self.status_label.configure(text=msg, text_color=COLOR_DANGEROUS)

    def _show_success(self, msg):
        self.status_label.configure(text=msg, text_color=COLOR_SAFE)

    def run(self):
        self.root.after(100, self.username_entry.focus_set)
        self.root.mainloop()
        return self.authenticated_username

    def _finish_login(self, username):
        self.authenticated_username = username
        try:
            self.root.destroy()
        except Exception:
            pass
        if self.on_success:
            self.on_success(username)
