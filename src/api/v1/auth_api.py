from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status
from sqlalchemy.ext.asyncio import AsyncSession




###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################

from db.db import  get_async_db
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.auth_schema import(
    LoginRequest , LoginResponse,
    CreateUserRequest , CreateUserResponse,
    SignupRequest , SignupResponse,
    UpdateUserRequest , UpdateUserResponse,
    RefreshAccessTokenRequest , RefreshAccessTokenResponse,
    DeleteUserRequest
)
from auth.crypto import hash_password , verify_password

from models.user_model import Users

from auth.jwt_auth import create_access_token , create_refresh_token , verify_token , verify_superadmin_token






auth_router = APIRouter()




@auth_router.post("/login" , response_model = standard_success_response[LoginResponse] , status_code=200)
async def login(req: LoginRequest ,  db: AsyncSession = Depends(get_async_db)):
    email = req.email
    password = req.password
    user = None

    result = await db.execute(select(Users).where(Users.email == email))
    user = result.scalars().first()
        
    
    if not user:
        raise HTTPException(status_code=401, detail="Email do not exist")
    
    if not verify_password(password , user.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    token_data = {
        "id" : user.id,
        "email": user.email,
        "role" : user.role
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    response = LoginResponse(access_token = access_token , refresh_token = refresh_token)
    return  standard_success_response(data = response , message = "Logged in successfully")







@auth_router.post("/signup" , response_model = standard_success_response[SignupResponse] , status_code=201)
async def signup(req: SignupRequest ,  db: AsyncSession = Depends(get_async_db)):

    result = await db.execute(select(Users).where(Users.email == req.email))
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=401, detail="User already exists with this email, please login")
    

    hashed_password = hash_password(req.password)

    new_user = Users(
        name = req.last,
        email = req.email,
        password = hashed_password,
        role = req.role
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    token_data = {
        "id" : new_user.id,
        "email": new_user.email,
        "role" : new_user.role
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    response = SignupResponse(access_token = access_token , refresh_token = refresh_token)
    return  standard_success_response(data = response , message = "Signed in successfully")



 




@auth_router.post("/refresh-access-token" , response_model = standard_success_response[RefreshAccessTokenResponse] , status_code=200)
async def refreshAccessToken(req: RefreshAccessTokenRequest):

    payload = verify_token(req.refresh_token)
    
    token_data = {
        "id" : payload["id"],
        "email": payload["email"],
        "role": payload["role"]
    }

    access_token = create_access_token(token_data)
    response = RefreshAccessTokenResponse(access_token = access_token)
    
    return  standard_success_response(data = response , message = "New Access token generated successfully")






@auth_router.post("/create-user" , response_model = standard_success_response[CreateUserResponse] , status_code=201)
async def signup(req: CreateUserRequest ,  db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_superadmin_token)):

    result = await db.execute(select(Users).where(Users.email == req.email))
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(status_code=401, detail="User already exists with this Email")
    

    hashed_password = hash_password(req.password)

    new_user = Users(
        name = req.name,
        email = req.email,
        password = hashed_password,
        role = req.role
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    
    
    response = CreateUserResponse(name = new_user.name , email = new_user.email , password = req.password , role = new_user.role)
    return  standard_success_response(data = response , message = "User Created successfully") 






@auth_router.put("/update-user" , response_model = standard_success_response[UpdateUserResponse] , status_code=200)
async def signup(req: UpdateUserRequest ,  db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_superadmin_token)):

    result = await db.execute(select(Users).where(Users.email == req.email))
    existing_user = result.scalars().first()

    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found with this email")
    

    hashed_password = hash_password(req.password)

    existing_user.name = req.name
    existing_user.password = hashed_password
    existing_user.role = req.role
    await db.commit()

    
    
    response = UpdateUserResponse(name = req.name , email = req.username , password = req.password , role = req.role)
    return  standard_success_response(data = response , message = "User Updated successfully") 






@auth_router.delete("/delete-user", status_code=204)
async def delete_user(req: DeleteUserRequest, db: AsyncSession = Depends(get_async_db), user: dict = Depends(verify_superadmin_token)):
    result = await db.execute(select(Users).where(Users.email == req.email))
    existing_user = result.scalars().first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found with this email")
    await db.delete(existing_user)
    await db.commit()
    return None