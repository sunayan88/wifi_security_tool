# ─────────────────────────────────────────
#  WiFi Security Tool — Database Setup
#  Run this once before starting the app
# ─────────────────────────────────────────

import os
import sys

# Make sure Python can find the project files
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import initialize_db
from config import DB_PATH


def setup():
    print("Setting up database...")

    # Create database folder if it doesn't exist
    db_folder = os.path.dirname(DB_PATH)
    if not os.path.exists(db_folder):
        os.makedirs(db_folder)
        print(f"  Created folder: {db_folder}")

    # Initialize tables
    initialize_db()

    print(f"  Database created at: {DB_PATH}")
    print("\nSetup complete. You can now run main.py")


if __name__ == "__main__":
    setup()