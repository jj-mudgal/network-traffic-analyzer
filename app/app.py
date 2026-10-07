"""Flask application factory for the Network Traffic Analyzer."""

from pathlib import Path

from flask import Flask, render_template

import database
from app.api import register_blueprints

ROOT = Path(__file__).resolve().parent.parent


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(ROOT / "templates"),
        static_folder=str(ROOT / "static"),
    )
    database.init_db()
    register_blueprints(app)

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    return app
