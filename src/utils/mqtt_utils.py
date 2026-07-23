import asyncio
import json
import uuid
import aiomqtt
from fastapi import HTTPException

# ---- config (match your broker) ----
MQTT_HOST = "80.225.239.163"      # or SERVER_IP
MQTT_PORT = 1883
MQTT_USER = "my_mqtt_user"
MQTT_PASS = "mqttpassword"



async def mqtt_request(agent_name: str, command: str,args: dict|None = None, timeout: float = 10.0) -> dict | None:
    """
    Publish a command to an agent and wait for its response.
    Returns the response dict, or None if the agent doesn't answer in time.
    """
    request_id = str(uuid.uuid4())
    command_topic  = f"server/command/{agent_name}"
    response_topic = f"agent/response/{agent_name}"
    payload = json.dumps({"command": command, "args" : args ,  "request_id": request_id})

    try:
        async with aiomqtt.Client(
            hostname=MQTT_HOST, port=MQTT_PORT,
            username=MQTT_USER, password=MQTT_PASS,
        ) as client:
            # subscribe BEFORE publishing so a fast reply isn't missed
            await client.subscribe(response_topic)
            await client.publish(command_topic, payload=payload)

            async def _wait():
                async for message in client.messages:
                    try:
                        data = json.loads(message.payload.decode())
                    except json.JSONDecodeError:
                        continue
                    if data.get("request_id") == request_id:
                        return data
                    # else: a reply for a different request — keep waiting

            return await asyncio.wait_for(_wait(), timeout=timeout)

    except asyncio.TimeoutError:
        return None                      # agent silent → your endpoint turns this into 504
    except aiomqtt.MqttError as e:
        raise HTTPException(503, f"MQTT error: {e}")