from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import OAuth2PasswordBearer
from manage_users import (
    add_user, change_user_role,
    delete_user, change_subordinates, list_users, change_password
)
from auth import login_user, change_own_password
from database import User, Function, Role
from sqlalchemy.orm import sessionmaker, joinedload
from sqlalchemy.exc import NoResultFound
from database import engine
import uvicorn

app = FastAPI()

Session = sessionmaker(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/login")
async def login(request: Request):
    data = await request.json()
    user_data = login_user(data['username'], data['password'])
    if not user_data:
        raise HTTPException(status_code=400, detail="Неправильное имя пользователя или пароль")
    return {"access_token": user_data["login"], "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    session = Session()
    try:
        user = session.query(User).filter_by(login=token).options(joinedload(User.subordinates)).one()
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
        user = session.query(User).options(joinedload(User.subordinates)).filter_by(login=user_login).one()
        if current_user.role_id == 2 and user.role_id not in[1, 2]:
            raise HTTPException(status_code=403, detail="Недостаточно прав для просмотра подчиненных")
        subordinates = user.subordinates
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


@app.post("/admin/users/{user_login}/change_password/", dependencies=[Depends(get_current_admin_user)])
async def admin_update_password(user_login: str, request: Request,
                                current_user: User = Depends(get_current_admin_user)):
    data = await request.json()
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        success = change_password(user.id, data["new_password"])
        if success != "Пароль изменен успешно":
            raise HTTPException(status_code=400, detail="Не удалось изменить пароль")
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
    session = Session()
    try:
        user = session.query(User).filter_by(login=user_login).one()
        result = delete_user(user.id)
        if result != "Пользователь удален успешно":
            raise HTTPException(status_code=400, detail=result)
        return {"message": result}
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/change_subordinates/", dependencies=[Depends(get_current_admin_user)])
async def update_subordinates(user_login: str, request: Request):
    try:
        data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON data: {str(e)}")

    session = Session()
    try:
        result = change_subordinates(user_login, data["new_subordinates_logins"])
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
        user = session.query(User).options(joinedload(User.subordinates)).filter_by(login=user_login).one()
        print(f"Current user role_id: {current_user.role_id}, requested user role_id: {user.role_id}")
        if current_user.role_id == 3 or current_user.login == user_login:
            return {"login": user.login, "age": user.age, "role_id": user.role_id, "last_login": user.last_login}
        elif current_user.role_id == 2:
            manager_subordinates = session.query(User).options(joinedload(User.subordinates)).filter_by(
                id=current_user.id).one().subordinates
            if user in manager_subordinates:
                return {"login": user.login, "age": user.age, "role_id": user.role_id, "last_login": user.last_login}
            else:
                raise HTTPException(status_code=403,
                                    detail="Недостаточно прав для просмотра профиля подчиненных другого руководителя")
        else:
            raise HTTPException(status_code=403, detail="Недостаточно прав для просмотра профиля")
    except NoResultFound:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    except Exception as e:
        print(f"Exception: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        session.close()


@app.post("/users/{user_login}/logout", dependencies=[Depends(get_current_active_user)])
async def logout(user_login: str, current_user: User = Depends(get_current_active_user)):
    if current_user.login != user_login:
        raise HTTPException(status_code=403, detail="Нельзя завершить сеанс другого пользователя")
    return {"message": "Сеанс завершен успешно"}


if __name__ == "__main__":
    try:
        uvicorn.run(app, host="127.0.0.1", port=8001)
    except KeyboardInterrupt:
        print("")
