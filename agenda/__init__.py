from flask import Flask

from agenda.api import api_blueprint # Import api variable from blueprint
from agenda.config import Config  # Importing Config class
from agenda.db import db  # Importing DB file

# Creates application, if requires further config, must be placed on this file
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)  # Passing Config class with custom variables (also DB  variables)  - RECOMMENDED
    #app.config.from_file(config)  # Passing Config file with custom variables

    # Starting DB connection, to connect use SQLALCHEMY_DATABASE_URI
    db.init_app(app)


    # Importing Blueprint / grouping routes
    app.register_blueprint(api_blueprint)

    # @app.route()  # Instance flask decorator
    @app.route("/healthycheck", methods=["GET"])
    def auth():
        return "Project Working Correctly!!!"

    @app.route("/bd/create", methods=["GET"])
    def create_db():
        result = db.create_all()
        return f"DB Created! {result}"

    @app.route("/bd/drop", methods=["GET"])
    def drop_db():
        result = db.drop_all('__all__')
        return f"DB Dropped! {result}"

    return app
