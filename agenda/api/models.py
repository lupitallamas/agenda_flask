from agenda.db import db
# Used to generated specific columns used by the model
from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy.sql import func
# Importing datatypes for creating Model
from sqlalchemy import Integer, String, DateTime, ForeignKey
import datetime




# Inheriting from db model created by SQLAlchemy
class User(db.Model):
    """User Object"""
    id = mapped_column(Integer, primary_key=True)
    first_name = mapped_column(String(255), nullable=False)
    last_name = mapped_column(String(255), nullable=True)
    email = mapped_column(String(100), unique=True)
    password = mapped_column(String(255), nullable=False)
    contacts = db.relationship("Contact", back_populates="users")



class Contact(db.Model):
    """Contact Object"""
    id = mapped_column(Integer, primary_key=True)
    first_name = mapped_column(String(255), nullable=False)
    last_name = mapped_column(String(255), nullable=True)
    email = mapped_column(String(100), unique=True)
    phone = mapped_column(String(100), unique=False)
    mobile = mapped_column(String(100), unique=True)
    user_id = mapped_column(Integer, ForeignKey("user.id"))
    users = db.relationship("User", back_populates="contacts")
    #created_at = mapped_column(DateTime, default=db.func.datetime)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
