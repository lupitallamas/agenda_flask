from flask_sqlalchemy import SQLAlchemy  # Importing Interface
from sqlalchemy.orm import DeclarativeBase  # Declaring ORM base

# Creating empty class
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base) # Passing empty class

# Execute to create all models
# db.create_all()

# Execute to drop tables created
# db.drop_all(__all__)