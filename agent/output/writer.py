import json
import threading
import asyncio
import os
import sys
from queue import Queue, Empty
from mqtt_producer import MQTTProducer
from config.unique_info import AGENT_NAME
from utils.utils import handle_command
import diskcache

 
MQTT_USER = "my_mqtt_user"
MQTT_PASS = "mqttpassword"
MQTT_TOPIC = "agent/agent_events"
MQTT_COMMAND_TOPIC = f"server/command/{AGENT_NAME}"
MAX_CACHE_EVENTS = 100000


from config.unique_info import SERVER_IP
MAX_CACHE_EVENTS = 100000

def _get_cache_dir():
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "retry_cache")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "retry_cache")


class EventDispatcher:
    def __init__(self, stdout: bool = False):
        self._queue      = Queue(maxsize=50000)
        self._stdout     = stdout
        self._stop       = threading.Event()
        self._loop       = None
        self._cache_lock = threading.Lock()
        self._retry_cache = diskcache.Cache(_get_cache_dir())

        self._mqtt = MQTTProducer(
            server_ip=SERVER_IP,
            mqtt_user=MQTT_USER,
            mqtt_pass=MQTT_PASS,
            mqtt_topic=MQTT_TOPIC,
            command_topic=MQTT_COMMAND_TOPIC,
            on_command=handle_command
        )

        self._thread = threading.Thread(
            target=self._thread_entry,
            daemon=True,
            name="sentinel-dispatcher"
        )
        self._thread.start()

    def _thread_entry(self):
        if sys.platform == "win32":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._worker())
        self._loop.close()

    async def _worker(self):
        print("Sentinel Dispatcher Pipeline Engine Active.")
        await self._mqtt.start()
        await self._flush_retry_cache()

        while not self._stop.is_set():
            try:
                event = await self._loop.run_in_executor(None, self._queue.get, True, 0.5)
                await self._push_with_retry(event)
                self._queue.task_done()
            except Empty:
                if len(self._retry_cache) > 0:
                    await self._flush_retry_cache()
                continue
            except Exception as e:
                print(f"Dispatcher error: {e}")
                await asyncio.sleep(2)

    async def _push_with_retry(self, event: dict):
        if not self._mqtt.is_connected():
            self._save_to_cache(event)
            return
        try:
            await asyncio.wait_for(
                self._mqtt.push(event.get("event"), event.get("machine_info")),
                timeout=5.0,
            )
            if self._stdout:
                print(f"Event pushed: {event.get('event', {}).get('type')}")
        except Exception as e:
            print(f"Push failed — caching for retry: {e}")
            self._save_to_cache(event)

    def _save_to_cache(self, event: dict):
        import time
        with self._cache_lock:
            if len(self._retry_cache) >= MAX_CACHE_EVENTS:
                oldest = next(iter(self._retry_cache.iterkeys()), None)
                if oldest:
                    self._retry_cache.delete(oldest)
                    print("Cache full — dropped oldest event.")
            key = f"retry_{time.time_ns()}_{id(event)}"
            self._retry_cache.set(key, json.dumps(event))
            print(f"Cached for retry (total: {len(self._retry_cache)})")

    async def _flush_retry_cache(self):
        if len(self._retry_cache) == 0:
            return

        if not self._mqtt.is_connected():
            return 
    
        print(f"Retrying {len(self._retry_cache)} cached events...")
        failed = 0

        for key in list(self._retry_cache.iterkeys()):
            try:
                raw = self._retry_cache.get(key)
                if raw is None:
                    self._retry_cache.delete(key)
                    continue

                event = json.loads(raw)
                await asyncio.wait_for(
                    self._mqtt.push(event.get("event"), event.get("machine_info")),
                    timeout=5.0,
                )
                self._retry_cache.delete(key)

            except Exception as e:
                failed += 1
                print(f"Retry failed: {e}")
                break   # stop immediately if connection is down

        if failed == 0:
            print("All cached events flushed successfully.")
        else:
            print(f"{failed} events still cached — will retry later.")

    def push(self, event_dict: dict, machine_info: dict | None):
        try:
            final_event = {"event": event_dict, "machine_info": machine_info}
            self._queue.put_nowait(final_event)
            if self._stdout:
                print(f"Event queued: {event_dict.get('type')}")
        except Exception:
            print("Queue full — saving directly to retry cache.")
            self._save_to_cache({"event": event_dict, "machine_info": machine_info})

    def flush_and_stop(self):
        print("Shutting down Dispatcher...")
        self._stop.set()
        self._thread.join(timeout=10)

        # drain in-memory queue to disk before exit
        drained = 0
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
                self._save_to_cache(event)
                drained += 1
            except Exception:
                break

        if drained > 0:
            print(f"Drained {drained} in-memory events to retry cache.")

        if len(self._retry_cache) > 0:
            print(f"{len(self._retry_cache)} events cached — will push on next startup.")

        self._retry_cache.close()
        print("Sentinel Agent stopped.")