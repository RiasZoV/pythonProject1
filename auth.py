from sqlalchemy.orm.exc import NoResultFound
from manage_users import hash_password
from database import User
from session_management import get_session
import bcrypt
from datetime import datetime
import pytz

def check_password(hashed_password, plain_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def login_user(login, password):
    """Аутентификация пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(login=login).one()
        if check_password(user.password, password):
            user.last_login = datetime.now(pytz.timezone('Europe/Moscow'))
            session.commit()
            session.close()
            return user
        else:
            session.close()
            return None
    except NoResultFound:
        session.close()
        return None

def change_own_password(user_id, old_password, new_password):
    """Изменение пароля пользователем"""
    session = get_session()
    user = session.query(User).filter_by(id=user_id).one()
    if check_password(user.password, old_password):
        user.password = hash_password(new_password)
        session.commit()
        session.close()
        return True
    else:
        session.close()
        return False


