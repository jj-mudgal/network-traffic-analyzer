"""Dev entry point.  Usage: python run.py [--seed] [--port 5000]"""

import argparse
import os

from dotenv import load_dotenv

load_dotenv()

import database  # noqa: E402  (after load_dotenv so DATABASE_PATH is honoured)
from app import create_app  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--seed", action="store_true", help="insert sample packets if the table is empty")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", 5000)))
    args = parser.parse_args()

    database.init_db()
    if args.seed:
        database.seed_sample_data()
    create_app().run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
