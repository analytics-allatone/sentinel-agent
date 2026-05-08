from pydantic import BaseModel





class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token : str
    refresh_token : str







class SignupRequest(BaseModel):
    first_name : str
    last_name : str
    email : str
    country_code :str
    phone_number : str
    password : str


class SignupResponse(BaseModel):
    access_token : str
    refresh_token : str








class ForgotPasswordRequest(BaseModel):
    email: str


class ForgotPasswordResponse(BaseModel):
    request_id : str








class ValidateForgotPasswordOTPRequest(BaseModel):
    request_id : str
    otp : str



class ValidateForgotPasswordOtpResponse(BaseModel):
    email : str








class SetNewPasswordRequest(BaseModel):
    email : str
    new_password : str


class SetNewPasswordResponse(BaseModel):
    pass









class RefreshAccessTokenRequest(BaseModel):
    refresh_token: str



class RefreshAccessTokenResponse(BaseModel):
    access_token : str

