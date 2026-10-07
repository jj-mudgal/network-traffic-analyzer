"""API blueprints."""


def register_blueprints(app):
    from app.api.routes import api

    app.register_blueprint(api)
