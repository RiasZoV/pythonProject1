from sqlalchemy.orm.exc import NoResultFound
from database import User, Role, Function
from session_management import get_session
import bcrypt


def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def get_user_by_login(login):
    session = get_session()
    try:
        user = session.query(User).filter_by(login=login).one()
        return user
    except NoResultFound:
        return None
    finally:
        session.close()


def add_user(login, password, role_name, age, subordinates=None):
    """Добавление нового пользователя в бд"""
    session = get_session()
    try:
        if session.query(User).filter_by(login=login).first():
            session.close()
            return f"Пользователь с логином '{login}' уже существует."

        role = session.query(Role).filter_by(name=role_name).one()
        hashed_password = hash_password(password)
        new_user = User(login=login, password=hashed_password, age=age, role_id=role.id)
        session.add(new_user)
        session.commit()

        if subordinates and role_name in ['Руководитель', 'Админ']:
            for sub_login in subordinates:
                try:
                    subordinate = session.query(User).filter_by(login=sub_login).one()
                    new_user.subordinates.append(subordinate)
                except NoResultFound:
                    session.close()
                    return f"Подчиненный пользователь '{sub_login}' не найден."
            session.commit()

        session.close()
        return f"Пользователь {login} добавлен успешно."
    except NoResultFound:
        session.close()
        return f"Роль '{role_name}' не найдена."
    finally:
        session.close()


def add_role(name):
    """Добавление новой роли в бд"""
    session = get_session()
    if session.query(Role).filter_by(name=name).first():
        return "Роль уже существует"
    new_role = Role(name=name)
    session.add(new_role)
    session.commit()
    session.close()
    return "Роль добавлена успешно"


def add_function(name, access_level, role_name):
    """Добавление новой функции в бд"""
    session = get_session()
    try:
        role = session.query(Role).filter_by(name=role_name).one()
        if session.query(Function).filter_by(name=name, role_id=role.id).first():
            return "Функция для этой роли уже существует"
        new_function = Function(name=name, access_level=access_level, role_id=role.id)
        session.add(new_function)
        session.commit()
        return "Функция добавлена успешно"
    except NoResultFound:
        return "Роль не найдена"
    finally:
        session.close()


def list_roles():
    """Вывод списка всех ролей"""
    session = get_session()
    roles = session.query(Role).all()
    session.close()
    return roles


def get_role_by_number(number):
    """Получение роли по номеру"""
    roles = list_roles()
    if 1 <= number <= len(roles):
        return roles[number - 1]
    else:
        return None


def list_subordinates(user_id):
    """Вывод списка подчиненных для пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(id=user_id).one()
        subordinates = user.subordinates
        return subordinates
    except NoResultFound:
        return []
    finally:
        session.close()


def change_password(user_id, new_password):
    """Изменение пароля для пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(id=user_id).one()
        user.password = hash_password(new_password)
        session.commit()
        return "Пароль изменен успешно"
    except NoResultFound:
        return "Пользователь не найден"
    finally:
        session.close()


def change_user_role(user_id, new_role_name):
    """Изменение роли пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(id=user_id).one()
        new_role = session.query(Role).filter_by(name=new_role_name).one()
        user.role_id = new_role.id
        session.commit()
        return "Роль изменена успешно"
    except NoResultFound:
        return "Пользователь или роль не найдены"
    finally:
        session.close()


def delete_user(user_id):
    """Удаление пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(id=user_id).one()
        session.delete(user)
        session.commit()
        return "Пользователь удален успешно"
    except NoResultFound:
        return "Пользователь не найден"
    finally:
        session.close()


def list_users():
    """Вывод списка всех пользователей"""
    session = get_session()
    users = session.query(User).all()
    users_list = [{"login": user.login, "role_id": user.role_id, "age": user.age} for user in users]
    session.close()
    return users_list


def change_subordinates(user_login, new_subordinates_logins):
    """Изменение списка подчиненных пользователя"""
    session = get_session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        user.subordinates = []
        for login in new_subordinates_logins:
            subordinate = session.query(User).filter_by(login=login).one()
            user.subordinates.append(subordinate)
        session.commit()
        return "Подчиненные обновлены успешно"
    except NoResultFound:
        return "Пользователь или подчиненные не найдены"
    finally:
        session.close()
