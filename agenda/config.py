import os
from dotenv import load_dotenv

load_dotenv() # Importing .env file

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    DB_NAME = os.getenv("BD_NAME")
    DB_HOST = os.getenv("BD_HOST")
    DB_USER = os.getenv("BD_USER")
    DB_PASSWORD = os.getenv("BD_PASSWORD")
    # Connection String to SQLAlchemy
    SQLALCHEMY_DATABASE_URI = (
        # Dialect for SQL
        f'postgresql://{os.getenv("BD_USER")}:{os.getenv("BD_PASSWORD")}@{os.getenv("BD_HOST")}/{os.getenv("BD_NAME")}'
    )
