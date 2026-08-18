"""Create or upgrade the WiFi Security Monitor database."""

from config import DB_PATH
from database.db_manager import initialize_db


def setup():
    print("Setting up database...")
    initialize_db()
    print(f"Database ready at: {DB_PATH}")
    print("Setup complete. You can now run main.py")


if __name__ == "__main__":
    setup()
