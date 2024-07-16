from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordBearer
from manage_users import (
    add_user, add_role, add_function, change_user_role,
    delete_user, change_subordinates, list_subordinates, list_users, get_user_by_login, is_subordinate
)
from auth import login_user, change_own_password, hash_password
from database import User, Function, Role
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import NoResultFound
from database import engine
import uvicorn

app = FastAPI()

Session = sessionmaker(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/login")
async def login(request: Request):
    data = await request.json()
    if 'username' not in data or 'password' not in data:
        raise HTTPException(status_code=400, detail="Отсутствует имя пользователя или пароль")
    user_info = login_user(data['username'], data['password'])
    if not user_info:
        raise HTTPException(status_code=400, detail="Неправильное имя пользователя или пароль")
    return {"access_token": user_info["login"], "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    session = Session()
    try:
        user = session.query(User).filter_by(login=token).one()
        return user
    except NoResultFound:
        raise HTTPException(status_code=401, detail="Неверные учетные данные для аутентификации")
    finally:
        session.close()


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user:
        return current_user
    raise HTTPException(status_code=401, detail="Неактивный пользователь")


async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role_id != 3:  # Предположим, что 3 - это id роли администратора
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    return current_user


async def get_current_manager_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role_id not in [2, 3]:  # Предположим, что 2 - это id роли менеджера
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    return current_user


async def get_current_regular_user(current_user: User = Depends(get_current_active_user)):
    if current_user.role_id not in [1, 2, 3]:  # Предположим, что 1 - это id роли пользователя
        raise HTTPException(status_code=403, detail="Недостаточно прав")
    return current_user


@app.post("/users/", dependencies=[Depends(get_current_admin_user)])
async def create_user(request: Request):
    data = await request.json()
    required_fields = ["login", "password", "age", "role_name"]
    for field in required_fields:
        if field not in data:
            raise HTTPException(status_code=400, detail=f"Отсутствует обязательное поле: {field}")
    result = add_user(data["login"], data["password"], data["role_name"], data["age"], data.get("subordinates"))
    if result != "Пользователь добавлен успешно":
        raise HTTPException(status_code=400, detail=result)
    return {"message": result}


@app.post("/roles/", dependencies=[Depends(get_current_admin_user)])
async def create_role(request: Request):
    data = await request.json()
    if 'name' not in data:
        raise HTTPException(status_code=400, detail="Отсутствует обязательное поле: name")
    result = add_role(data["name"])
    if result != "Роль добавлена успешно":
        raise HTTPException(status_code=400, detail=result)
    return {"message": result}


@app.post("/functions/", dependencies=[Depends(get_current_admin_user)])
async def create_function(request: Request):
    data = await request.json()
    required_fields = ["name", "access_level", "role_name"]
    for field in required_fields:
        if field not in data:
            raise HTTPException(status_code=400, detail=f"Отсутствует обязательное поле: {field}")
    result = add_function(data["name"], data["access_level"], data["role_name"])
    if result != "Функция добавлена успешно":
        raise HTTPException(status_code=400, detail=result)
    return {"message": result}


@app.get("/users/", dependencies=[Depends(get_current_admin_user)])
async def get_users():
    session = Session()
    try:
        users = list_users()
        return users
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.get("/roles/", dependencies=[Depends(get_current_admin_user)])
async def get_roles():
    session = Session()
    try:
        roles = session.query(Role).all()
        return [{"id": role.id, "name": role.name} for role in roles]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.get("/functions/", dependencies=[Depends(get_current_admin_user)])
async def get_functions():
    session = Session()
    try:
        functions = session.query(Function).all()
        return [{"name": func.name, "access_level": func.access_level, "role_id": func.role_id} for func in functions]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.get("/users/{user_login}/subordinates", dependencies=[Depends(get_current_manager_user)])
async def get_subordinates(user_login: str, current_user: User = Depends(get_current_manager_user)):
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()

        # Проверка на подчиненность
        if current_user.role_id == 2 and not is_subordinate(current_user.id, user.id) and user.id != current_user.id:
            raise HTTPException(status_code=403,
                                detail="Недостаточно прав для просмотра подчиненных другого руководителя")

        subordinates = list_subordinates(user.id)
        if not subordinates:
            return []
        return [{"login": sub.login, "age": sub.age, "role_id": sub.role_id} for sub in subordinates]
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/change_password/", dependencies=[Depends(get_current_active_user)])
async def update_password(user_login: str, request: Request, current_user: User = Depends(get_current_active_user)):
    data = await request.json()
    required_fields = ["old_password", "new_password"]
    for field in required_fields:
        if field not in data:
            raise HTTPException(status_code=400, detail=f"Отсутствует обязательное поле: {field}")
    session = Session()
    try:
        if current_user.login != user_login:
            raise HTTPException(status_code=403, detail="Нельзя менять чужой пароль")
        success = change_own_password(current_user.id, data["old_password"], data["new_password"])
        if not success:
            raise HTTPException(status_code=400, detail="Старый пароль неправильный")
        return {"message": "Пароль изменен успешно"}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/change_role/", dependencies=[Depends(get_current_admin_user)])
async def update_role(user_login: str, request: Request):
    data = await request.json()
    if 'new_role_name' not in data:
        raise HTTPException(status_code=400, detail="Отсутствует обязательное поле: new_role_name")
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        result = change_user_role(user.id, data["new_role_name"])
        if result != "Роль изменена успешно":
            raise HTTPException(status_code=400, detail=result)
        return {"message": result}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/delete/", dependencies=[Depends(get_current_admin_user)])
async def remove_user(user_login: str):
    try:
        user = get_user_by_login(user_login)
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        result = delete_user(user.id)
        if result != "Пользователь удален успешно":
            raise HTTPException(status_code=400, detail=result)
        return {"message": result}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/users/{user_login}/change_subordinates/", dependencies=[Depends(get_current_admin_user)])
async def update_subordinates(user_login: str, request: Request):
    data = await request.json()
    if 'new_subordinates_logins' not in data:
        raise HTTPException(status_code=400, detail="Отсутствует обязательное поле: new_subordinates_logins")
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        result = change_subordinates(user.id, data["new_subordinates_logins"])
        if result != "Подчиненные обновлены успешно":
            raise HTTPException(status_code=400, detail=result)
        return {"message": result}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.get("/users/{user_login}/profile", dependencies=[Depends(get_current_active_user)])
async def view_profile(user_login: str, current_user: User = Depends(get_current_active_user)):
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()

        # Обычный пользователь может видеть только свой профиль
        if current_user.role_id == 1 and current_user.login != user_login:
            raise HTTPException(status_code=403, detail="Недостаточно прав для просмотра профиля другого пользователя")

        # Руководитель может видеть только профили своих подчиненных
        if current_user.role_id == 2 and user.id != current_user.id and not is_subordinate(current_user.id, user.id):
            raise HTTPException(status_code=403, detail="Недостаточно прав для просмотра профиля этого пользователя")

        return {"login": user.login, "age": user.age, "role_id": user.role_id, "last_login": user.last_login}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/logout", dependencies=[Depends(get_current_active_user)])
async def logout(user_login: str, current_user: User = Depends(get_current_active_user)):
    if current_user.role_id != 3 and current_user.login != user_login:
        raise HTTPException(status_code=403, detail="Нельзя завершить сеанс другого пользователя")
    return {"message": "Сеанс завершен успешно"}


@app.post("/users/{user_login}/admin_change_password/", dependencies=[Depends(get_current_admin_user)])
async def admin_change_password(user_login: str, request: Request):
    data = await request.json()
    if 'new_password' not in data:
        raise HTTPException(status_code=400, detail="Отсутствует обязательное поле: new_password")
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        user.password = hash_password(data["new_password"])
        session.commit()
        return {"message": "Пароль изменен успешно администратором"}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


if __name__ == "__main__":
    try:
        uvicorn.run(app, host="127.0.0.1", port=8001)
    except KeyboardInterrupt:
        print("")
