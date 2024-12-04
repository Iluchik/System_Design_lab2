from typing_extensions import Unpack
from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, RootModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from uuid import uuid4

SECRET_KEY = "System-design-Lab2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = 20

app = FastAPI()

# ==== Data Base ======================================================================================================

class User(BaseModel):
	id: int
	name: str
	email: str
	password: str
	age: Optional[int] = None
	adress: Optional[str] = None
	phone: Optional[str] = None

class Package_discription(BaseModel):
	package_details: dict
	recipient_id: int

class Package(Package_discription):
	sender_id: int
	product_id: str

# Авторизированные пользователи
online_users = []

# БД с аккаунтами всех пользователей
client_DB = [
	User(id=0, name="admin", email="admin@email.com", password="$2b$12$RUwSLi48Uityyl22Uyy/v.LKql2LAixQEj0S5f4oE4Hyk6GG8syLu", age=22)
]

# Черный список токенов доступа
token_BL = []

# БД посылок
package_DB = []

# =====================================================================================================================

# ==== User service ===================================================================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def authentification(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Invalid credentials",
		headers={"WWW-Authenticate": "Bearer"}
	)
	try:
		if token in token_BL:
			raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is expired")
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		email: str = payload.get("sub")
		for client in client_DB:
			if email == client.email:
				return {"user": client, "token": token}
		else:
			raise credentials_exception
	except JWTError:
		raise credentials_exception

def authorization(data: dict, expires_delta: Optional[timedelta] = None):
	payload = data.copy()
	if expires_delta:
		expire = datetime.utcnow() + expires_delta
	else:
		expire = datetime.utcnow() + ACCESS_TOKEN_EXPIRE_MIN
	payload.update({"exp": expire})
	token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
	return token

@app.post("/users", response_model=User)
def create_user(user: User):
	for client in client_DB:
		if client.id == user.id:
			raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exist")
	user.password = pwd_context.hash(user.password)
	client_DB.append(user)
	return user

@app.post("/token", response_model=dict[str, str])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), email: str = Form(...)):
	password_check = False
	user = None
	for client in client_DB:
		if form_data.username == client.name:
			user = client
			password = client.password
			if pwd_context.verify(form_data.password, password):
				password_check = True
	if password_check:
		expire = timedelta(ACCESS_TOKEN_EXPIRE_MIN)
		access_token = authorization(data={"sub": email}, expires_delta=expire)
		online_users.append(user)
		return {"access_token": access_token, "token_type": "bearer"}
	else:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"}
		)

@app.get("/users", response_model=List[User])
def get_online(current_user: dict = Depends(authentification)):
	return online_users

@app.get("/users/{user_id}", response_model=User)
def get_client(user_id: int, current_user: dict = Depends(authentification)):
	for client in client_DB:
		if client.id == user_id:
			return client
	raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

@app.put("/users", response_model=User)
def update_client(updated_client: User, current_user: dict = Depends(authentification)):
	for i, client in enumerate(client_DB):
		if client.id == current_user["user"].id:
			client_DB[i] = updated_client
			for i, user in enumerate(online_users):
				if user.id == current_user["user"].id:
					online_users[i] = update_client
			return updated_client
	raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

@app.delete("/users/delete", response_model=User)
def delete_account(current_user: dict = Depends(authentification)):
	for i, client in enumerate(client_DB):
		if client.id == current_user["user"].id:
			deleted_user = client_DB.pop(i)
			return deleted_user
	raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

@app.delete("/users", response_model=User)
def logout(current_user: dict = Depends(authentification)):
	for i, user in enumerate(online_users):
		if user.id == current_user["user"].id:
			logout_user = online_users.pop(i)
			token_BL.append(current_user["token"])
			return logout_user
	raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

# =====================================================================================================================

# ==== Package service ================================================================================================

@app.post("/package", response_model=Package)
def create_package(package: Package_discription, current_user: dict = Depends(authentification)):
	new_package = Package(package_details=package.package_details, recipient_id=package.recipient_id, sender_id=current_user["user"].id, product_id=uuid4().hex)
	package_DB.append(new_package)
	return new_package

@app.get("/package", response_model=List[Package])
def get_user_packages(current_user: dict = Depends(authentification)):
	packages = []
	for product in package_DB:
		if product.sender_id == current_user["user"].id:
			packages.append(product)
	return packages

@app.put("/package", response_model=Package)
def update_package(updated_package: Package, current_user: dict = Depends(authentification)):
	for i, product in enumerate(package_DB):
		if product.product_id == updated_package.product_id:
			package_DB[i] = updated_package
			return updated_package

@app.delete("/package/{product_id}", response_model=Package)
def delete_package(product_id: str, current_user: dict = Depends(authentification)):
	for i, product in enumerate(package_DB):
		if product.product_id == product_id:
			deleted_product = package_DB.pop(i)
			return deleted_product

# =====================================================================================================================

if __name__ == "__main__":
	import uvicorn
	uvicorn.run(app, host="0.0.0.0", port=8000)