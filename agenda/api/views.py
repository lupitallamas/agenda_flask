from . import api_blueprint
from . import models
from datetime import datetime, timedelta
from functools import wraps
#import jwt  # Importin JWt library (for token)
from flask import request, make_response
from werkzeug.security import generate_password_hash, check_password_hash  # Security tool for encrypting passwords
from agenda.db import  db


# Defining specific method functions, using single function
@api_blueprint.post("/users/auth")
def auth(request):
    data = request.data
    return data


@api_blueprint.route("/health", methods=["GET"])
def health():
    return "Project Working Correctly from API !!!"


@api_blueprint.route("/signup/", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return {"detail": "email required"}, 400

        # Creating DB connection
    user_exist = db.session.execute(
        # Select from User model (select * from user where email = user_exist
        db.select(models.User).where(models.User.email == email)
    ).scalar_one_or_none()

    # Methods allowed with scalar
    # .scalar()  -  Can be used when returns more than one register
    # .scalar_one() - Just one result, checks if exist or not
    # .scalar_one_or_none() - Just one result, checks if exist or not
    if user_exist:
        return {"detail": "Email already taken"}, 400

    passowrd = data.get("password")
    user = models.User(
        first_name = data.get("first_name"),
        last_name = data.get("last_name"),
        email = email,
        password = generate_password_hash(passowrd),  # Encrypting password
    )

    db.session.add(user)
    db.session.commit()
    return {"detail": "User created successfully"}, 201