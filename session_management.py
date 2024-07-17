from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import DATABASE_URL

# Создание двигателя для соединения с бд
engine = create_engine(DATABASE_URL)

Session = sessionmaker(bind=engine)

def get_session():
    """Получение новой сессии"""
    return Session()



