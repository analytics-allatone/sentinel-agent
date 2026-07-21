import asyncio
import json
import inspect
import threading
from datetime import datetime

import aiomqtt


class MQTTProducer:
    """
    aiomqtt publisher + command listener.

    - Publishes events (push).
    - Subscribes to server/command/{agent} and runs on_command for each.
    - Publishes replies to agent/response/{agent} echoing the request_id.
    """

    def __init__(self, server_ip, mqtt_user, mqtt_pass, mqtt_topic,
                 agent_name: str,
                 command_topic: str = None, response_topic: str = None,
                 on_command=None, reconnect_delay: float = 60.0):
        self.server_ip = server_ip
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass
        self.mqtt_topic = mqtt_topic
        self.agent_name = agent_name

        # default topics if not supplied
        self.command_topic  = command_topic  or f"server/command/{agent_name}"
        self.response_topic = response_topic or f"agent/response/{agent_name}"
        self.on_command = on_command
        self.reconnect_delay = reconnect_delay

        self._client = None
        self._connected = False
        self._stop = asyncio.Event()
        self._reconnect = asyncio.Event()
        self._conn_task = None

    # ---- connection state ------------------------------------------------

    def is_connected(self) -> bool:
        return self._connected

    async def start(self):
        if self._conn_task is None:
            self._stop.clear()
            self._conn_task = asyncio.create_task(self._connection_manager())

    async def stop(self):
        self._stop.set()
        if self._conn_task:
            try:
                await asyncio.wait_for(self._conn_task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._conn_task.cancel()
        self._connected = False

    async def _connection_manager(self):
        while not self._stop.is_set():
            try:
                async with aiomqtt.Client(
                    hostname=self.server_ip, port=1883,
                    username=self.mqtt_user, password=self.mqtt_pass,
                ) as client:
                    self._client = client
                    self._connected = True
                    self._reconnect.clear()
                    print("[MQTT] connected")

                    # subscribe to the command topic on every (re)connect
                    await client.subscribe(self.command_topic)
                    print(f"[MQTT] listening for commands on {self.command_topic}")

                    # run the message listener alongside the stop/reconnect waiters
                    listen_t = asyncio.ensure_future(self._listen(client))
                    stop_t   = asyncio.ensure_future(self._stop.wait())
                    recon_t  = asyncio.ensure_future(self._reconnect.wait())
                    done, pending = await asyncio.wait(
                        {listen_t, stop_t, recon_t},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in pending:
                        t.cancel()

                self._connected = False
                self._client = None
                if self._stop.is_set():
                    break

            except aiomqtt.MqttError as e:
                self._connected = False
                self._client = None
                print(f"[MQTT] connect failed: {e} — retrying in {self.reconnect_delay:.0f}s")
                await self._wait_or_stop(self.reconnect_delay)
            except Exception as e:
                self._connected = False
                self._client = None
                print(f"[MQTT] unexpected error: {e} — retrying in {self.reconnect_delay:.0f}s")
                await self._wait_or_stop(self.reconnect_delay)

        self._connected = False
        print("[MQTT] connection manager stopped")

    async def _wait_or_stop(self, delay):
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    # ---- command listening + responding ----------------------------------

    async def _listen(self, client):
        """Read command messages and dispatch each to on_command."""
        async for message in client.messages:
            try:
                payload = json.loads(message.payload.decode())
            except json.JSONDecodeError:
                print(f"[MQTT] bad command payload: {message.payload}")
                continue

            request_id = payload.get("request_id")
            try:
                # on_command runs the actual work; may be sync or async
                if inspect.iscoroutinefunction(self.on_command):
                    result = await self.on_command(payload)
                else:
                    result = self.on_command(payload)
            except Exception as e:
                result = {"error": str(e)}

            # publish the reply, echoing the request_id for correlation
            await self._respond(request_id, payload.get("command"), result)

    async def _respond(self, request_id, command, result):
        if not self._client:
            return
        reply = json.dumps(
            {"request_id": request_id, "command": command, "result": result},
            default=self._default_serializer,
        )
        try:
            await self._client.publish(self.response_topic, payload=reply)
        except aiomqtt.MqttError as e:
            print(f"[MQTT] failed to publish response: {e}")

    # ---- publishing ------------------------------------------------------

    async def push(self, event, machine_info={}):
        """Publish one event. Raises MqttError if offline so caller can cache."""
        if not self._connected or self._client is None:
            raise aiomqtt.MqttError("not connected")

        payload = {"machine_info": machine_info, "event": event}
        json_string = json.dumps(payload, default=self._default_serializer)
        try:
            await self._client.publish(self.mqtt_topic, payload=json_string)
        except aiomqtt.MqttError:
            self._connected = False
            self._reconnect.set()
            raise

    def _default_serializer(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="ignore")
        raise TypeError(f"Type not serializable: {type(obj)}")