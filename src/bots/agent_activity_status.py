from sqlalchemy import select

from utils.mqtt_utils import mqtt_request
from db.db import get_async_session
import asyncio
from models.agent_model import Agents



async def check_active(agent_name):
    result = await mqtt_request(agent_name=agent_name, command =  "active_test",timeout=10.0)
    return result



async def check_active_status():
    while(True):
        async with get_async_session() as session:
                    res = await session.execute(select(Agents))
                    res = res.scalars().all()
                    for a in res:
                        print(f"Testing for agent : {a.agent_name}")
                        result = await check_active(a.agent_name)
                        print(f"Testing Response for agent : {a.agent_name} : {result}")

                        if result:
                            a.is_active = True
                            a.status = res.get("status")
                        else:
                            a.is_active = False
                            a.status = "disconnected" if a.mac_address is not None else "never_connected"
                    await session.commit()

        await asyncio.sleep(3)
