from . import api_blueprint
from . import models
from datetime import datetime, timedelta
from functools import wraps
import jwt  # Importin JWt library (for token)
from flask import request, make_response
from werkzeug.security import generate_password_hash, check_password_hash  # Security tool for encrypting passwords
from agenda.db import  db
from agenda.config import Config



# Token Validation Decorator
def token_required(func):
    @wraps(func)  # Mandatory user this decorator, flask do not accept simple decorators
    def wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization")
        prefix = 'Bearer '
        if not authorization:
            return {"detail": "Missing Authorization header"}, 401

        if not authorization.startswith(prefix):
            return {"detail": "Invalid Token Prefix"}, 401

        print(f"Authorization Value: {authorization}")
        token = authorization.split(" ")[1]

        if not token:
            return {"detail": "Missing Token"}, 401

        # Validates token still valid
        try:
            payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        except jwt.exceptions.ExpiredSignatureError:
            return {"detail" : "Token Expired"}, 401
        except jwt.exceptions.InvalidTokenError:
            return {"detail" : "Invalid Token"}, 401

        request.user = db.session.execute(
            db.select(models.User).where(models.User.id == payload["sub"])
        ).scalar_one()
        return func(*args, **kwargs)

    return wrapper



# Protected Resource
@api_blueprint.post("/users/auth/")
@token_required
def auth():
    data = request.get_json()
    data = data.get("data")
    data = data + ' modified'
    return {"detail": f"{data}", "user_id": f"{request.user.id}"}

# Check Running App
@api_blueprint.route("/health", methods=["GET"])
def health():
    return "Project Working Correctly from API !!!"



# Create User
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



# Get Token
@api_blueprint.route("/login/", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return {"detail": "Missing email or password"}, 400

    user = db.session.execute(
        db.select(models.User).where(models.User.email == email)
    ).scalar_one_or_none()

    # Checking if password is correct and also if user exist
    if not user or not check_password_hash(user.password, password):
        return {"detail": "Invalid email or password"}, 401

    # Specify subject and expire date on JWT Token
    # Token will expire in 30 min
    token = jwt.encode(
        {
            "sub": user.id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=30),
        },
        Config.SECRET_KEY,
        )
    return {"token": token}




@api_blueprint.route("/contacts/<int:contact_id>", methods=["GET", "PUT", "DELETE"])
@api_blueprint.route("/contacts/", methods=["GET", "POST"])
@token_required
def contacts_endpoint(contact_id=None):
    try:
        data = request.get_json()
    except:
        pass

    if contact_id is not None:
        contact = models.Contact.query.get_or_404(contact_id, 'Contact not found!!')

        if request.method == 'GET':
            return {
                    "id": contact.id,
                    "first_name": contact.first_name,
                    "last_name": contact.last_name,
                    "email": contact.email,
                    "phone": contact.phone,
                    "mobile": contact.mobile,
                    "user_id": contact.user_id,
                    "created_at": contact.created_at
                    }

        if request.method == 'PUT':
            contact.first_name = data['first_name']
            contact.last_name = data['last_name']
            contact.phone = data['phone']
            contact.mobile = data['mobile']
            contact.email = data['email']
            db.session.commit()
            return {"detail": f"Contact {contact.email} was modified!!"}


    if request.method == 'GET':
        contacts_all = models.Contact.query.all()
        # Returning object stored on dict using list comprehension
        return [{
            "id": contact.id,
            "first_name": contact.first_name,
            "last_name": contact.last_name,
            "phone": contact.phone,
            "mobile": contact.mobile,
            "email": contact.email,
            "user_id": contact.user_id,
            "created_at": contact.created_at
        } for contact in contacts_all]

    if request.method == "POST":
        # Creating object
        contact_instance = models.Contact(
                                        first_name=data["first_name"],
                                        last_name=data["last_name"],
                                        phone = data["phone"],
                                        mobile=data["mobile"],
                                        email=data["email"],
                                        user_id = request.user.id,
                                        )
        # Creating DB connection, and creating record
        db.session.add(contact_instance)
        # Applying Changes
        db.session.commit()
        return {"detail":f"Contact {contact_instance.email} created successfully!!"}

    if request.method == "DELETE":
        # Checking specie exist
        contact = models.Contact.query.get_or_404(contact_id, "Pet not Found!!")
        # Passing specie object to be deleted
        db.session.delete(contact)
        # Committing changes
        db.session.commit()

        return {"detail": f"Contact {contact.email} deleted successfully!!"}