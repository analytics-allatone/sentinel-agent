import json
import threading
from queue import Queue, Empty

from kafka_producer import KafkaWriter


class EventDispatcher:
    def __init__(
        self,
        kafka_brokers: str,
        kafka_topic: str,
        stdout: bool = False,
    ):
        self._queue = Queue(maxsize=50000)
        self._stdout = stdout
        self._stop = threading.Event()

        self._kafka = KafkaWriter(
            brokers=kafka_brokers,
            topic=kafka_topic
        )

        self._thread = threading.Thread(
            target=self._worker,
            daemon=True,
            name="sentinel-dispatcher"
        )

        self._thread.start()

    def _worker(self):
        while not self._stop.is_set():

            try:
                event = self._queue.get(timeout=1)

                self._kafka.write(event)

            except Empty:
                continue

            except Exception as e:
                print(f"Dispatcher error: {e}")

    def push(self, event_dict: dict):
        try:
            self._queue.put_nowait(event_dict)

        except Exception:
            print("Event queue full, dropping event")

    def flush_and_stop(self):
        self._stop.set()

        self._thread.join(timeout=10)

        self._kafka.flush()