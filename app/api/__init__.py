"""API blueprints."""


def register_blueprints(app):
    from app.api.routes import api
    from app.api.alerts import alerts_api
    from app.api.capture_routes import capture_api

    app.register_blueprint(api)
    app.register_blueprint(alerts_api)
    app.register_blueprint(capture_api)
