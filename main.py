"""Application entry point. Administrator mode enables fuller Windows scans."""

import ctypes

from database.db_manager import initialize_db
from gui.app import App
from gui.login import LoginWindow


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main():
    if not is_admin():
        print("[WARNING] Some features require Administrator privileges.")
        print("          Restart as Administrator for full Windows scan results.\n")

    initialize_db()

    # Logout returns to a fresh sign-in screen without restarting the process.
    while True:
        username = LoginWindow().run()
        if not username:
            break
        if App(username=username).run() != "logout":
            break


if __name__ == "__main__":
    main()
