from agenda.db import db
from sqlalchemy import Integer, String, DateTime, Date
from sqlalchemy.orm import mapped_column
from datetime import datetime, date

class User(db.Model):
    id = mapped_column(Integer, primary_key=True)
    first_name = db.Column(String(length=50), nullable=False)
    last_name = db.Column(String(length=50), nullable=True)
    email = db.Column(String, unique=True, nullable=False)
    password = db.Column(String, nullable=False)
    contacts= db.relationship("Contact", back_populates="users")
    
class Contact(db.Model):
    """Contact object"""
    
    id = db.Column(Integer, primary_key= True)
    first_name = db.Column(String(length=50), nullable=False)
    last_name = db.Column(String(length=50), nullable=True)
    phone = db.Column(String, unique=False, nullable=True)
    mobile = db.Column(String, unique=True, nullable=False)
    email = db.Column(String, unique=True, nullable=False)
    user_id = db.Column(Integer, db.ForeignKey("user.id"))
    users = db.relationship("User", back_populates="contacts")
    create_at = db.Column(Date)
    
   
