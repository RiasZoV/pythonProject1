from manage_users import (
    add_user, add_role, add_function, list_subordinates, change_password,
    change_user_role, delete_user, list_users, change_subordinates, get_user_by_login, list_roles, get_role_by_number
)
from auth import login_user, change_own_password
from session_management import get_session
from database import Role, User, Function


def admin_actions(admin_user):
    """
    Действия администратора.

    :param admin_user: Объект текущего пользователя.
    :type admin_user: User
    """
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

        action_input = input("Введите номер действия: ").strip()
        if not action_input.isdigit():
            print("Некорректный ввод. Попробуйте снова.")
            continue

        action_num = int(action_input)
        if action_num == 1:
            view_profile(admin_user)
        elif action_num == 2:
            new_login = input("Введите логин нового пользователя: ").strip()
            new_password = input("Введите пароль нового пользователя: ").strip()
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер роли нового пользователя: ").strip())
            new_role = get_role_by_number(role_num)
            new_age = int(input("Введите возраст нового пользователя: ").strip())
            add_user(new_login, new_password, new_role.name, new_age)
        elif action_num == 3:
            user_login_to_delete = input("Введите login пользователя для удаления: ").strip()
            user_to_delete = get_user_by_login(user_login_to_delete)
            delete_user(user_to_delete.id)
        elif action_num == 4:
            user_login_to_change = input("Введите login пользователя для изменения роли: ").strip()
            user_to_change = get_user_by_login(user_login_to_change)
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер новой роли: ").strip())
            new_role = get_role_by_number(role_num)
            change_user_role(user_to_change.id, new_role.name)
        elif action_num == 5:
            list_users()
        elif action_num == 6:
            user_login_to_change_pwd = input("Введите login пользователя для смены пароля: ").strip()
            user_to_change_pwd = get_user_by_login(user_login_to_change_pwd)
            new_password = input("Введите новый пароль: ").strip()
            change_password(user_to_change_pwd.id, new_password)
        elif action_num == 7:
            user_login_to_change_sub = input("Введите login пользователя для изменения подчиненных: ").strip()
            user_to_change_sub = get_user_by_login(user_login_to_change_sub)
            subordinates_logins = input("Введите логины новых подчиненных через запятую: ").strip().split(',')
            change_subordinates(
                user_to_change_sub.id,
                [login.strip() for login in subordinates_logins]
            )
        elif action_num == 8:
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def manager_actions(manager_user):
    """
    Действия менеджера.

    :param manager_user: Объект текущего пользователя.
    :type manager_user: User
    """
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

        action_input = input("Введите номер действия: ").strip()
        if not action_input.isdigit():
            print("Некорректный ввод. Попробуйте снова.")
            continue

        action_num = int(action_input)
        if action_num == 1:
            view_profile(manager_user)
        elif action_num == 2:
            list_subordinates(manager_user.id)
        elif action_num == 3:
            subordinate_login = input("Введите login подчиненного для смены пароля: ").strip()
            subordinate = get_user_by_login(subordinate_login)
            new_password = input("Введите новый пароль: ").strip()
            change_password(subordinate.id, new_password)
        elif action_num == 4:
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def user_actions(regular_user):
    """
    Действия обычного пользователя.

    :param regular_user: Объект текущего пользователя.
    :type regular_user: User
    """
    actions = {
        1: "view_profile",
        2: "change_password",
        3: "logout"
    }

    while True:
        print("Выберите действие:")
        for num, action in actions.items():
            print(f"{num} - {action}")

        action_input = input("Введите номер действия: ").strip()
        if not action_input.isdigit():
            print("Некорректный ввод. Попробуйте снова.")
            continue

        action_num = int(action_input)
        if action_num == 1:
            view_profile(regular_user)
        elif action_num == 2:
            old_password = input("Введите старый пароль: ").strip()
            new_password = input("Введите новый пароль: ").strip()
            change_own_password(regular_user.id, old_password, new_password)
        elif action_num == 3:
            print("Выход из системы.")
            break
        else:
            print("Неизвестное действие. Попробуйте снова.")
    return False  # Return to indicate logout


def view_profile(user):
    """
    Просмотр профиля пользователя.

    :param user: Объект текущего пользователя.
    :type user: User
    """
    print(f"Профиль пользователя:\nЛогин: {user.login}\nВозраст: {user.age}")


def initialize_database():
    """
    Инициализация базы данных: добавление ролей и функций при первом запуске.
    """
    local_session = get_session()

    # Проверка, существуют ли уже роли и функции
    if not local_session.query(Role).first():
        add_role('Пользователь')
        add_role('Руководитель')
        add_role('Админ')

    if not local_session.query(Function).first():
        add_function('Просмотр данных', 1, 'Пользователь')
        add_function('Редактирование данных', 2, 'Руководитель')
        add_function('Управление пользователями', 3, 'Админ')

    local_session.close()


def add_initial_users():
    """
    Добавление начальных пользователей при первом запуске.
    """
    local_session = get_session()
    if not local_session.query(User).first():
        print("Заполнение базы данных начальными пользователями...")
        while True:
            user_login = input("Введите логин пользователя: ").strip()
            user_password = input("Введите пароль пользователя: ").strip()
            roles = list_roles()
            print("Доступные роли:")
            for idx, role in enumerate(roles, 1):
                print(f"{idx} - {role.name}")
            role_num = int(input("Введите номер роли пользователя: ").strip())
            role = get_role_by_number(role_num)
            user_age = int(input("Введите возраст пользователя: ").strip())
            subordinates_input = None
            if role.name in ['Руководитель', 'Админ']:
                subordinates_input = input(
                    "Введите логины подчиненных пользователей через запятую (если есть): ").strip()
            subordinates = [s.strip() for s in subordinates_input.split(',')] if subordinates_input else None

            add_user(user_login, user_password, role.name, user_age, subordinates)

            another = input("Хотите добавить еще одного пользователя? (да/нет): ").strip().lower()
            if another != 'да':
                break
    local_session.close()


if __name__ == "__main__":
    try:
        initialize_database()
        add_initial_users()

        while True:
            login_name = input("Введите логин для входа: ").strip()
            login_password = input("Введите пароль для входа: ").strip()
            current_user = login_user(login_name, login_password)

            if current_user:
                session = get_session()
                current_user = session.query(User).filter_by(login=login_name).one()
                if current_user.role_id == 1:  # Пользователь
                    if not user_actions(current_user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: "
                        ).strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
                elif current_user.role_id == 2:  # Руководитель
                    if not manager_actions(current_user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: "
                        ).strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
                elif current_user.role_id == 3:  # Админ
                    if not admin_actions(current_user):
                        next_action = input(
                            "Введите 'exit' для выхода из программы или 'login' для входа под другим пользователем: "
                        ).strip().lower()
                        if next_action == 'exit':
                            print("Программа завершена.")
                            break
            else:
                print("Не удалось войти. Попробуйте снова.")
    except KeyboardInterrupt:
        print("\nПрограмма завершена")
