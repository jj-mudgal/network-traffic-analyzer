"""API blueprints."""


def register_blueprints(app):
    from app.api.routes import api
    from app.api.alerts import alerts_api

    app.register_blueprint(api)
    app.register_blueprint(alerts_api)