from pydantic import BaseModel
from typing import List


class User(BaseModel):
    id: str
    username: str
    password: str
    role: str


class Role(BaseModel):
    id: int
    name: str


class UserCreate(BaseModel):
    username: str
    password: str
    role_name: str
    permissions: List[str] = []
