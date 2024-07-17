from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import pytz

DATABASE_URL = 'sqlite:///users.db'

# Создание двигателя для соединения с бд
engine = create_engine(DATABASE_URL)

# Создание базового класса для декларативного стиля
Base = declarative_base()

# таблица подчиненных
subordinates_table = Table('subordinates', Base.metadata,
                           Column('user_login', String, ForeignKey('users.login')),
                           Column('subordinate_login', String, ForeignKey('users.login'))
                           )


# Определение таблицы User
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)
    age = Column(Integer, nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    last_login = Column(DateTime, default=lambda: datetime.now(pytz.timezone('Europe/Moscow')))
    subordinates = relationship('User', secondary=subordinates_table,
                                primaryjoin=login == subordinates_table.c.user_login,
                                secondaryjoin=login == subordinates_table.c.subordinate_login,
                                backref='superiors')


# Определение таблицы Role
class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)


# Определение таблицы Function
class Function(Base):
    __tablename__ = 'functions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, unique=True)
    access_level = Column(Integer, nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)


# Создание всех таблиц в бд
Base.metadata.create_all(engine)

# print("База данных и таблицы созданы успешно!")
