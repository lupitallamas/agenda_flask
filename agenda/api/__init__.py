from flask import  Blueprint

# Declaring Blueprint instance
api_blueprint = Blueprint("api", __name__, url_prefix='/api')

# Need import views to make them visible
from . import views
from . import models