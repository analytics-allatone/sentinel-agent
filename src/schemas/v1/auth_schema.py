from pydantic import BaseModel
from typing import Optional




class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token : str|None
    refresh_token : str|None
    two_fa_enabled : bool
    challenge_token:str|None



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



class TwoFASetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_png_base64: str




class TwoFACodeRequest(BaseModel):
    code: str


class TwoFAEnableResponse(BaseModel):
    two_fa_enabled: bool


class TwoFAVerifyRequest(BaseModel):
    challenge_token: str
    code: str


class TwoFADisableRequest(BaseModel):
    password: str
    code: str
