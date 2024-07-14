from manage_users import (
    add_user, add_role, add_function, list_subordinates, change_password,
    change_user_role, delete_user, list_users, change_subordinates, get_user_by_login, list_roles, get_role_by_number
)
from auth import login_user, change_own_password
from session_management import get_session
from database import Role, User, Function


def admin_actions(user):
    actions = {
        1: "view_profile",
        2: "add",
        3: "delete",
        4: "change_role",
        5: "list",
        6: "change_password",
        7: "change_subordinates",
        8: "logout"
    }

    while True:
        print("Выберите действие:")
        for num, action in actions.items():
            print(f"{num} - {action}")

        action = input("Введите номер действия: ").strip()
        if action.isdigit():
            action_num = int(action)
        if action == "view_profile":
            view_profile(user)
        elif action == "add":
            new_login = input("Введите логин нового пользователя: ").strip()
            new_password = input("Введите пароль нового пользователя: ").strip()
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер роли нового пользователя: ").strip())
            new_role = get_role_by_number(role_num)
            age = int(input("Введите возраст нового пользователя: ").strip())
            add_user(new_login, new_password, new_role.name, age)
        elif action == "delete":
            user_login = input("Введите login пользователя для удаления: ").strip()
            user_to_delete = get_user_by_login(user_login)
            delete_user(user_to_delete.id)
        elif action == "change_role":
            user_login = input("Введите login пользователя для изменения роли: ").strip()
            user_to_change = get_user_by_login(user_login)
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер новой роли: ").strip())
            new_role = get_role_by_number(role_num)
            change_user_role(user_to_change.id, new_role.name)
        elif action == "list":
            list_users()
        elif action == "change_password":
            user_login = input("Введите login пользователя для смены пароля: ").strip()
            user_to_change = get_user_by_login(user_login)
            new_password = input("Введите новый пароль: ").strip()
            change_password(user_to_change.id, new_password)
        elif action == "change_subordinates":
            user_login = input("Введите login пользователя для изменения подчиненных: ").strip()
            user_to_change = get_user_by_login(user_login)
            subordinates_logins = input("Введите логины новых подчиненных через запятую: ").strip().split(',')
            change_subordinates(user_to_change.id, [login.strip() for login in subordinates_logins])
        elif action == "logout":
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def manager_actions(user):
    actions = {
        1: "view_profile",
        2: "list_subordinates",
        3: "change_password",
        4: "logout"
    }

    while True:
        print("Выберите действие:")
        for num, action in actions.items():
            print(f"{num} - {action}")

        action_num = int(input("Введите номер действия: ").strip())
        action = actions.get(action_num)

        if action == "view_profile":
            view_profile(user)
        elif action == "list_subordinates":
            list_subordinates(user.id)
        elif action == "change_password":
            subordinate_login = input("Введите login подчиненного для смены пароля: ").strip()
            subordinate = get_user_by_login(subordinate_login)
            new_password = input("Введите новый пароль: ").strip()
            change_password(subordinate.id, new_password)
        elif action == "logout":
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def user_actions(user):
    actions = {
        1: "view_profile",
        2: "change_password",
        3: "logout"
    }

    while True:
        print("Выберите действие:")
        for num, action in actions.items():
            print(f"{num} - {action}")

        action_num = int(input("Введите номер действия: ").strip())
        action = actions.get(action_num)

        if action == "view_profile":
            view_profile(user)
        elif action == "change_password":
            old_password = input("Введите старый пароль: ").strip()
            new_password = input("Введите новый пароль: ").strip()
            change_own_password(user.id, old_password, new_password)
        elif action == "logout":
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def view_profile(user):
    """Просмотр профиля пользователя"""
    print(f"Профиль пользователя:\nЛогин: {user.login}\nВозраст: {user.age}")


def initialize_database():
    """Добавление ролей и функций только при первом запуске"""
    session = get_session()

    # Проверка, существуют ли уже роли и функции
    if not session.query(Role).first():
        add_role('Пользователь')
        add_role('Руководитель')
        add_role('Админ')

    if not session.query(Function).first():
        add_function('Просмотр данных', 1, 'Пользователь')
        add_function('Редактирование данных', 2, 'Руководитель')
        add_function('Управление пользователями', 3, 'Админ')

    session.close()


def add_initial_users():
    """Добавление начальных пользователей только при первом запуске"""
    session = get_session()
    if not session.query(User).first():
        print("Заполнение базы данных начальными пользователями...")
        while True:
            login = input("Введите логин пользователя: ").strip()
            password = input("Введите пароль пользователя: ").strip()
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер роли пользователя: ").strip())
            role = get_role_by_number(role_num)
            age = int(input("Введите возраст пользователя: ").strip())
            subordinates_input = None
            if role.name in ['Руководитель', 'Админ']:
                subordinates_input = input(
                    "Введите логины подчиненных пользователей через запятую (если есть): ").strip()
            subordinates = [s.strip() for s in subordinates_input.split(',')] if subordinates_input else None

            add_user(login, password, role.name, age, subordinates)

            another = input("Хотите добавить еще одного пользователя? (да/нет): ").strip().lower()
            if another != 'да':
                break
    session.close()


if __name__ == "__main__":
    try:
        initialize_database()
        add_initial_users()

        while True:
            login = input("Введите логин для входа: ").strip()
            password = input("Введите пароль для входа: ").strip()
            user = login_user(login, password)

            if user:
                session = get_session()
                user = session.query(User).filter_by(login=login).one()
                if user.role_id == 1:  # Пользователь
                    if not user_actions(user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: ").strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
                elif user.role_id == 2:  # Руководитель
                    if not manager_actions(user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: ").strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
                elif user.role_id == 3:  # Админ
                    if not admin_actions(user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: ").strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
            else:
                print("Не удалось войти. Попробуйте снова.")
    except KeyboardInterrupt:
        print("\nПрограмма завершена")
