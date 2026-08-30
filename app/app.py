import os

from flask import Flask, jsonify

from app.api.routes import api

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    app.register_blueprint(api)

    @app.get("/")
    def index():
        return jsonify(
            {
                "name": "Network Traffic Analyzer",
                "status": "running",
                "message": "Flask backend is running",
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)