from pydantic import BaseModel



class OneCommunicationChannel(BaseModel):
    id: int
    name: str
    value: str

class CommunicationChannelGroup(BaseModel):
    channel_type : str
    channels : list[OneCommunicationChannel]

class getCommunicationChannelsResponse(BaseModel):
    communication_channels : list[CommunicationChannelGroup]


class addCommunicationChannelRequest(BaseModel):
    type : str
    name: str
    value: str


class addCommunicationChannelResponse(BaseModel):
    id: int
    type : str
    name: str
    value: str