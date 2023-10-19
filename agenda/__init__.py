from flask import Flask
from .api import api
from .config import Confing
from .db import db

def create_app():
    
    app = Flask(__name__)
    
    app.config.from_object(Confing)
    
    db.init_app(app)
   
    app.register_blueprint(api)
    
    @app.route("/init_db")
    def init_db():
        db.create_all()
        return "DataBase Create"
    
    @app.route("/drop_db")
    def drop_db():
        db.drop_all()
        return "Database Droppedlo Koders!"
    
    @app.route("/")
    def hello():
        return "Hello amiguitos" 
    return app
