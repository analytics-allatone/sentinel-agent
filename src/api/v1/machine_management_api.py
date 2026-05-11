from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException , status
from sqlalchemy.ext.asyncio import AsyncSession



###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################
from db.db import  get_async_db
from utils.machine_validator import validate_ssh , run_ssh_command
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.machine_management_schema import(
    ValidateMachineRequest , ValidateMachineResponse,
    AddMachineRequest , AddMachineResponse
)

from models.user_model import Users
from models.machines_model import Machines

from auth.jwt_auth import verify_token




machine_management_router = APIRouter()



@machine_management_router.get("/validate-machine" , response_model = standard_success_response[ValidateMachineResponse] , status_code=200)
async def ValidateMachine(req : ValidateMachineRequest):
    host = req.host
    username = req.username
    password = req.password
    private_key = req.private_key
    auth_type = req.auth_type
    port = req.port

    valid = await validate_ssh(host = host , username = username ,  password=password , private_key= private_key , port = port , auth_type= auth_type)
    if valid:
        response = ValidateMachineResponse()
        return standard_success_response(data = response , message = "Machine validated successfully")
    
    raise HTTPException(
        status_code=401,
        detail="SSH authentication failed"
    )




@machine_management_router.post("/add-machine" , response_model = standard_success_response[AddMachineResponse] , status_code=201)
async def addMachine(req: AddMachineRequest ,  db: AsyncSession = Depends(get_async_db) , user:dict = Depends(verify_token)):
    host = req.host
    username = req.username
    password = req.password
    private_key = req.private_key
    auth_type = req.auth_type
    auth_type 
    port = req.port

    name = req.name
    cloud_provider = req.cloud_provider
    region = req.region
    os_type = req.os_type
    os_type = os_type.lower()
    user_id = user.get('id')
    
    is_valid = await validate_ssh(host = host , username = username ,  password=password , private_key= private_key , port = port , auth_type= auth_type)
    
    if not is_valid:
        raise HTTPException(
        status_code=401,
        detail="SSH authentication failed"
    )

    this_machine = Machines(
        name = name,
        host = host,
        port = port,
        username = username,

        auth_type = auth_type,
        private_key = private_key,
        password = password,

        cloud_provider = cloud_provider,
        region = region,
        os_type = os_type,
        user_id = user_id

    )

    db.add(this_machine)

    await db.commit()
    await db.refresh(this_machine)

    response = AddMachineResponse(

        id  = this_machine.id,
        name = this_machine.name,
        host = this_machine.host,
        port = this_machine.port,
        username = this_machine.username,
        auth_type = this_machine.auth_type,
        private_key = this_machine.private_key,
        password = this_machine.password,
        cloud_provider = this_machine.cloud_provider,
        region = this_machine.region,
        os_type = this_machine.os_type,
        is_active = this_machine.is_active
    )

    return standard_success_response(data = response , message = "Machine Added successfully")
