from pydantic import BaseModel
from typing import Optional




class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token : str
    refresh_token : str



class CreateUserRequest(BaseModel):
    name: str
    email: str
    password: str
    role : str


class CreateUserResponse(BaseModel):
    name: str
    email: str
    password: str
    role : str


class SignupRequest(BaseModel):
    name : str
    email : str
    password : str
    role : str


class SignupResponse(BaseModel):
    access_token : str
    refresh_token : str



class UpdateUserRequest(BaseModel):
    email : str
    name : Optional[str]
    password : Optional[str]
    role : Optional[str]


class UpdateUserResponse(BaseModel):
    email:str
    name: str
    password : str
    role : str



class DeleteUserRequest(BaseModel):
    email: str



class RefreshAccessTokenRequest(BaseModel):
    refresh_token: str



class RefreshAccessTokenResponse(BaseModel):
    access_token : str


class ApplicationUser(BaseModel):
    name: str
    email: str
    password : str
    role : str



class GetUsersResponse(BaseModel):
    users : list[ApplicationUser]