from flask import request, make_response
from agenda.db  import db
from . import api
from .models import User, Contact
from datetime import datetime, timedelta
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from agenda.config  import Confing

import hashlib



# Token Validation Decorator
def token_required(func):
    @wraps(func)  # Mandatory user this decorator, flask do not accept simple decorators
    def wrapper():
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
            db.select(User).where(User.id == payload["sub"])
        ).scalar_one()
        return func()

    return wrapper



# Protected Resource
@api.post("/users/auth/")
@token_required
def auth():
    data = request.get_json()
    data = data.get("data")
    data = data + ' modified'
    return {"detail": f"{data}", "user_id": f"{request.user.id}"}

# Check Running App
@api.route("/health", methods=["GET"])
def health():
    return "Project Working Correctly from API !!!"



# Create User
@api.route("/signup/", methods=["POST"])
def signup():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return {"detail": "email required"}, 400

        # Creating DB connection
    user_exist = db.session.execute(
        # Select from User model (select * from user where email = user_exist
        db.select(User).where(User.email == email)
    ).scalar_one_or_none()

    # Methods allowed with scalar
    # .scalar()  -  Can be used when returns more than one register
    # .scalar_one() - Just one result, checks if exist or not
    # .scalar_one_or_none() - Just one result, checks if exist or not
    if user_exist:
        return {"detail": "Email already taken"}, 400

    password = data.get("password")
    user = User(
        first_name = data.get("first_name"),
        last_name = data.get("last_name"),
        email = email,
        #password= generate_password_hash(password, method='pbkdf2')
        password = generate_password_hash(password)  # Encrypting password
    )

    db.session.add(user)
    db.session.commit()
    return {"detail": "User created successfully"}, 201



# Get Token
@api.route("/login/", methods=["POST"])
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
#-------------------------------------------------------------------------------
"""Todos los contactos de un Usuario"""
@api.route("user/<int:user_id>/", methods=["GET"])
def contats_user(user_id=None):
    try:
        data = request.get_json()
    except:
        pass
    
    contacts = Contact.query.all()
    return [{"id": contact.id, 
             "first_name": contact.first_name, 
             "last_name": contact.last_name,
             "user_id":contact.user_id,
             "phone": contact.phone,
             "mobile": contact.mobile,
             "email": contact.email} for contact in contacts if contact.user_id == user_id
        ]
    
    
"""manejo del contacto"""
@api.route("/contacts/<int:contact_id>", methods=["GET", "PUT", "DELETE"])
@api.route("/contacts/", methods=["GET", "POST"])
def contacts_endpoinst(contact_id=None):
    try:
        data = request.get_json()
    except:
        pass

    if contact_id is not None:
        contact = Contact.query.get_or_404(contact_id, "Contact not found") 
        if request.method == "GET":
            user = User.query.get(contact.user_id)
            return {"id": contact.id, 
                    "first_name": contact.first_name, 
                    "last_name":contact.last_name,
                    "phone": contact.phone,
                    "mobile": contact.mobile,
                    "user_id":contact.id,
                    "Usuario:":user.first_name,
                    "Usuari last_name":user.last_name
                    }
 
        if request.method == "PUT":
            contact.first_name = data["first_name"]
            contact.last_name = data["last_name"]
            contact.phone = data["phone"]
            contact.mobile = data["mobile"]
            contact.email= data["email"]
            msg = f"Contact: {contact.id}  {contact.first_name} {contact.last_name} modified"

        if request.method == "DELETE":
                db.session.delete(contact)
                msg = f"contact: {contact.id}  {contact.first_name} {contact.last_name} {contact.user_id} deleted"
            
        db.session.commit()
        return {"detail": msg}

    if request.method == "GET":
        contacts = Contact.query.all()
        return [{"id": contact.id, 
                 "first_name": contact.first_name, 
                 "last_name": contact.last_name,
                 "user_id":contact.user_id,
                 "phone": contact.phone,
                 "mobile": contact.mobile,
                 "email": contact.email} for contact in contacts
                ]

    if request.method == "POST":
        date=datetime.strptime(data["create_at"],'%d/%m/%Y')
        date=datetime.date(date)
        
        user = User.query.get_or_404(data["user_id"], "User not Found")
        
        contact = Contact(
            first_name = data["first_name"],
            last_name = data["last_name"],
            phone = data["phone"],
            mobile = data["mobile"],
            email = data["email"],
            user_id = data["user_id"],
            create_at = date
        )
        db.session.add(contact)
        db.session.commit()

        return {"detail": f"contact {contact.id} {contact.first_name} {contact.last_name}   created successfully"}

