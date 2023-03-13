from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt_utils import generate_token, verify_password, decode_token, get_password_hash
from user_model import User
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


from models.model import UserCreate

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# Set up MySQL database
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://user:password@localhost/fastapi_jwt"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Define User model with a relationship to the Role model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(100))
    role_id = Column(Integer, ForeignKey("roles.id"))

    role = relationship("Role", back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True)
    permissions = Column(String(100))

    users = relationship("User", back_populates="role")


Base.metadata.create_all(bind=engine)


# Authentication and authorization functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_by_username(db, username: str):
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def get_current_user(db, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    user_id = payload.get("sub")
    role = payload.get("role")
    if user_id is None or role is None:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_role_by_name(db, name: str):
    return db.query(Role).filter(Role.name == name).first()


def get_role(current_user: User = Depends(get_current_user)):
    db = SessionLocal()
    try:
        role = get_role_by_name(db, current_user.role.name)
        if role is None:
            raise HTTPException(status_code=403, detail="Role not found")
        return role
    finally:
        db.close()


def has_permission(current_user: User = Depends(get_current_user), permission: str = ""):
    db = SessionLocal()
    try:
        role = get_role(db)
        if permission not in role.permissions:
            raise HTTPException(status_code=403, detail="Permission denied")
    finally:
        db.close()


def create_user(db, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    role = get_role_by_name(db, user.role_name)
    db_user = User(username=user.username, hashed_password=hashed_password, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Create a new user with the "admin" role and permissions "read" and "write"
with SessionLocal() as db:
    role = Role(name="admin", permissions=["read", "write"])
    db.add(role)
    db.commit()
    user = UserCreate(username="admin", password="password", role_name="admin")
    create_user(db, user)
