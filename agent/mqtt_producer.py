import asyncio
import json
from datetime import datetime
import aiomqtt
import threading
import inspect



class MQTTProducer:
    def __init__(self, server_ip, mqtt_user, mqtt_pass, mqtt_topic , command_topic: str = None, on_command=None):
        self.server_ip = server_ip
        self.mqtt_user = mqtt_user 
        self.mqtt_pass = mqtt_pass
        self.mqtt_topic = mqtt_topic
        self.command_topic = command_topic
        self.on_command = on_command
        self._client = None  # Persistent client to avoid connecting on every single push
        # self._sub_thread   = None
        # self._stop_sub     = threading.Event()

        # if self.command_topic and self.on_command:
        #     self._start_subscriber()
    

    def _start_subscriber(self):
        """Start subscriber in its own thread with its own event loop."""
        self._sub_thread = threading.Thread(
            target=self._subscriber_thread_entry,
            daemon=True,
            name="sentinel-subscriber"
        )
        self._sub_thread.start()
        print(f"Subscriber started on topic: {self.command_topic}")

    def _subscriber_thread_entry(self):
        import sys
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._subscriber_worker())
        loop.close()

    async def _subscriber_worker(self):
        """Subscribes to command topic and calls on_command for each message."""
        while not self._stop_sub.is_set():
            try:
                async with aiomqtt.Client(
                    hostname=self.server_ip,
                    port=1883,
                    username=self.mqtt_user,
                    password=self.mqtt_pass
                ) as client:
                    await client.subscribe(self.command_topic)
                    print(f"Subscribed to: {self.command_topic}")

                    async for message in client.messages:
                        if self._stop_sub.is_set():
                            break
                        try:
                            payload = json.loads(message.payload.decode())
                            print(f"Command received on {message.topic}: {payload}")
                            # call the handler
                            
                            if inspect.iscoroutinefunction(self.on_command):
                                await self.on_command(payload)
                            else:
                                self.on_command(payload)
                        except json.JSONDecodeError:
                            print(f"Invalid JSON on command topic: {message.payload}")
                        except Exception as e:
                            print(f"Command handler error: {e}")

            except aiomqtt.MqttError as e:
                print(f"Subscriber connection lost: {e} — reconnecting in 5s")
                await asyncio.sleep(5)
            except Exception as e:
                print(f"Subscriber error: {e} — reconnecting in 5s")
                await asyncio.sleep(5)

    def stop_subscriber(self):
        """Stop the subscriber thread cleanly."""
        self._stop_sub.set()
        if self._sub_thread:
            self._sub_thread.join(timeout=5)
            print("Subscriber stopped.")



    def _default_serializer(self, obj):
        """Custom encoder for non-standard data types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            # 🌟 FIX: Convert raw bytes in your events (like hashes or IDs) to string!
            return obj.decode('utf-8', errors='ignore')
        raise TypeError(f"Type not serializable: {type(obj)}")

    async def push(self, event , machine_info = {}):
        """Pushes a single log item cleanly to the MQTT broker."""
        try:
            # 1. Nest the dictionary objects completely BEFORE converting to JSON string
            full_payload_dict = {
                "machine_info" : machine_info,
                "event": event
            }
            print(full_payload_dict)
            # 2. Serialize the combined dictionary using the custom handler
            json_string = json.dumps(full_payload_dict, default=self._default_serializer)
            
            # 3. Use an active connection if it exists, otherwise create a new context
            if self._client is None:
                self._client = aiomqtt.Client(
                    hostname=self.server_ip,
                    port=1883,
                    username=self.mqtt_user,
                    password=self.mqtt_pass
                )
                await self._client.__aenter__()

            # 4. Publish exactly once (NO while True loop here!)
            # aiomqtt accepts either raw strings or encoded bytes for the payload parameter
            await self._client.publish(self.mqtt_topic, payload=json_string)

        except aiomqtt.MqttError as error:
            print(f"⚠️ Error pushing to MQTT server: {error}")
            # Reset client reference on failure to force reconnection next cycle
            self._client = None
            raise error  # Let EventDispatcher's try-except block catch this and handle the sleep
            
        except TypeError as err:
            print(f"❌ Serialization Failure: {err}")
