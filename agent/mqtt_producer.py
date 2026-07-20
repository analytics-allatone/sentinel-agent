import asyncio
import json
import inspect
import requests
import threading
from datetime import datetime

import aiomqtt


class MQTTProducer:
    """
    aiomqtt publisher with a background connection manager.

    aiomqtt has no auto-reconnect and no is_connected() of its own, so this
    class owns a persistent connection in a background task, exposes a real
    is_connected() flag, and retries every `reconnect_delay` seconds when down.

    Usage (from the dispatcher's event loop):
        await producer.start()      # launch the connection manager once
        if producer.is_connected():
            await producer.push(event, machine_info)
    """

    def __init__(self, server_ip, mqtt_user, mqtt_pass, mqtt_topic,
                 command_topic: str = None, on_command=None,
                 reconnect_delay: float = 60.0):
        self.server_ip = server_ip
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass
        self.mqtt_topic = mqtt_topic
        self.command_topic = command_topic
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
        """Launch the background connection manager. Call once on the loop."""
        if self._conn_task is None:
            self._stop.clear()
            self._conn_task = asyncio.create_task(self._connection_manager())

    async def stop(self):
        """Tear down the connection manager cleanly."""
        self._stop.set()
        if self._conn_task:
            try:
                await asyncio.wait_for(self._conn_task, timeout=5)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._conn_task.cancel()
        self._connected = False

    async def _connection_manager(self):
        """Hold a live connection; reconnect every reconnect_delay on failure."""
        while not self._stop.is_set():
            try:
                async with aiomqtt.Client(
                    hostname=self.server_ip,
                    port=1883,
                    username=self.mqtt_user,
                    password=self.mqtt_pass,
                ) as client:
                    self._client = client
                    self._connected = True
                    self._reconnect.clear()
                    print("[MQTT] connected")

                    # stay connected until stop or a push signals a reconnect
                    stop_t = asyncio.ensure_future(self._stop.wait())
                    recon_t = asyncio.ensure_future(self._reconnect.wait())
                    done, pending = await asyncio.wait(
                        {stop_t, recon_t}, return_when=asyncio.FIRST_COMPLETED
                    )
                    for t in pending:
                        t.cancel()

                self._connected = False
                self._client = None
                if self._stop.is_set():
                    break
                # else a reconnect was requested → loop and reconnect now

            except aiomqtt.MqttError as e:
                self._connected = False
                self._client = None
                print(f"[MQTT] connect failed: {e} — retrying in "
                      f"{self.reconnect_delay:.0f}s")
                await self._wait_or_stop(self.reconnect_delay)
            except Exception as e:
                self._connected = False
                self._client = None
                print(f"[MQTT] unexpected error: {e} — retrying in "
                      f"{self.reconnect_delay:.0f}s")
                await self._wait_or_stop(self.reconnect_delay)

        self._connected = False
        print("[MQTT] connection manager stopped")

    async def _wait_or_stop(self, delay):
        """Sleep for `delay`, but wake immediately if stop is requested."""
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

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
            # connection died mid-publish: flag it and kick the manager to reconnect
            self._connected = False
            self._reconnect.set()
            raise

        except aiomqtt.MqttError as error:
            print(f"⚠️ Error pushing to MQTT server: {error}")
            # Reset client reference on failure to force reconnection next cycle
            self._client = None
            raise error  # Let EventDispatcher's try-except block catch this and handle the sleep
            
        except TypeError as err:
            print(f"❌ Serialization Failure: {err}")
        finally :
            agent_name="agent1"
            API="http://127.0.0.1:8000"
            requests.post(f"{API}/api/agents/{agent_name}/detected-event", json=event)

    def _default_serializer(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode("utf-8", errors="ignore")
        raise TypeError(f"Type not serializable: {type(obj)}")
