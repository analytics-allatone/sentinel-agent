from sqlalchemy.future import select
from fastapi import APIRouter , Depends , HTTPException, Query , status
from sqlalchemy.ext.asyncio import AsyncSession




###############################################
#                                             #
#              LOCAL MODULES IMPORT           #
#                                             #
###############################################

from db.db import  get_async_db
from schemas.v1.standard_schema import standard_success_response
from schemas.v1.communication_schema import (
    CommunicationChannelGroup , OneCommunicationChannel,
    getCommunicationChannelsResponse , addCommunicationChannelResponse,
    addCommunicationChannelRequest
)
from models.user_model import CommunicationChannel

from auth.jwt_auth import verify_token , verify_superadmin_token , verify_admin_token


communication_router = APIRouter()


@communication_router.get("/communication-channels" , response_model = standard_success_response[getCommunicationChannelsResponse] , status_code=200)
async def get_communication_channels(db: AsyncSession = Depends(get_async_db) ,
                                     user:dict = Depends(verify_token)):
    channel_result = await db.execute(select(CommunicationChannel))
    existing_channels = channel_result.scalars().all()

    res = []
    cat = {}
    for ch in existing_channels:
        id = ch.id
        tp = ch.type
        nm = ch.name
        val = ch.value
        if cat.get(tp) is not None:
            cat[tp].append(OneCommunicationChannel(id = id, name = nm , value = val))
        else:
            cat[tp] = [OneCommunicationChannel(id = id, name = nm , value = val)]

    for key , val in cat.items():
        res.append(CommunicationChannelGroup(channel_type=key , channels = val))

    res_data = getCommunicationChannelsResponse(communication_channels=res)
    return standard_success_response(data = res_data , message = "Communication Channels Fetched successfully")






@communication_router.post("/add-communication-channels" , response_model = standard_success_response[addCommunicationChannelResponse] , status_code=201)
async def add_communication_channels(req : addCommunicationChannelRequest,
                                     db: AsyncSession = Depends(get_async_db) ,
                                     user:dict = Depends(verify_admin_token)):
    channel_result = await db.execute(select(CommunicationChannel).where(CommunicationChannel.name == req.name))
    existing_channels = channel_result.scalars().one_or_none()
    if existing_channels is not None:
        raise HTTPException(status_code = 401 , detail = "Channel already exist with this name")

    new_channel = CommunicationChannel(
        name = req.name,
        type = req.type,
        value = req.value
    )
    db.add(new_channel)
    await db.commit()
    await db.refresh(new_channel)
    

    res_data = addCommunicationChannelResponse(id = new_channel.id ,
                                               type = new_channel.type,
                                               name = new_channel.name,
                                               value = new_channel.value
                                               )
    return standard_success_response(data = res_data , message = "Communication Channels Added successfully")






@communication_router.delete("/delete-communicaiton-channel", status_code=200)
async def delete_communicaiton_channel(communication_channel_id: int = Query(),
                            db: AsyncSession = Depends(get_async_db),
                            user: dict = Depends(verify_admin_token)):
    """Remove a stored credential."""

    credential = await db.get(CommunicationChannel, communication_channel_id)
    if not credential:
        raise HTTPException(status_code=404, detail="Communication channel not found")
    await db.delete(credential)
    await db.commit()

    return standard_success_response(data={"id": communication_channel_id},
                                     message="Credential deleted successfully")
