from sqlalchemy import select

from utils.mqtt_utils import mqtt_request
from db.db import get_async_session
import asyncio
from models.agent_model import Agents

CONCURRENCY = 20



async def check_active(agent_name):
    try:
        return await mqtt_request(agent_name=agent_name, command="active_test", timeout=10.0)
    except Exception as e:
        return None


async def check_active_status():
    sem = asyncio.Semaphore(CONCURRENCY)

    async def probe(name):
        async with sem:
            return name, await check_active(name)

    while True:
        try:
            # read the agent list, then release the session before any MQTT work
            async with get_async_session() as session:
                agents = (await session.execute(select(Agents))).scalars().all()
                names = [a.agent_name for a in agents]

            results = dict(await asyncio.gather(*(probe(n) for n in names)))
            async with get_async_session() as session:
                agents = (await session.execute(select(Agents))).scalars().all()
                for a in agents:
                    reply = results.get(a.agent_name)
                    result = reply.get("result") if isinstance(reply, dict) else None
                    if result:
                        a.is_active = True
                        a.status = result.get("status")          
                    else:
                        a.is_active = False
                        a.status = "disconnected" if a.mac_address else "never_connected"
                await session.commit()

        except Exception:
            print("exception occured")

        await asyncio.sleep(120)