import asyncio
import orjson
import os

from confluent_kafka import Consumer, KafkaException
from dotenv import load_dotenv

load_dotenv()


KAFKA_CONFIG = {
    "bootstrap.servers": os.environ.get("KAFKA_BOOTSTRAP_SERVER"),
    "group.id": "sentinel-consumer-group",

    "enable.auto.commit": False,
    "auto.offset.reset": "latest",

    # batching optimization
    "fetch.min.bytes": 1024,
    "fetch.wait.max.ms": 500,
}


TOPIC = os.environ.get("KAFKA_TOPIC")


BATCH_SIZE = 1000
FLUSH_INTERVAL = 5


class KafkaConsumerService:

    def __init__(self):

        self.running = True
        self.consumer = None

        self.message_buffer = []

    def start(self):

        self.consumer = Consumer(KAFKA_CONFIG)

        self.consumer.subscribe([TOPIC])

        print("Kafka Consumer Started")

    async def process_batch(self, messages):

        """
        Your business logic here.
        """

        parsed_messages = []

        for msg in messages:

            data = orjson.loads(msg.value())

            parsed_messages.append(data)

        print("\n========== BATCH RECEIVED ==========")

        for data in parsed_messages:
            print(data)

        print("====================================\n")

    async def flush(self):

        if not self.message_buffer:
            return

        batch = self.message_buffer

        self.message_buffer = []

        try:

            # PROCESS WHOLE BATCH
            await self.process_batch(batch)

            # COMMIT ONLY AFTER SUCCESS
            self.consumer.commit(
                asynchronous=False
            )

            print(f"Committed {len(batch)} messages")

        except Exception as e:

            print("Batch Processing Error:", e)

            # restore messages if failed
            self.message_buffer.extend(batch)

    async def consume_loop(self):

        while self.running:

            try:

                messages = self.consumer.consume(
                    num_messages=BATCH_SIZE,
                    timeout=1.0
                )

                if not messages:
                    await asyncio.sleep(0.1)
                    continue

                valid_messages = []

                for msg in messages:

                    if msg.error():
                        print("Kafka Message Error:", msg.error())
                        continue

                    valid_messages.append(msg)

                if not valid_messages:
                    continue

                await self.process_batch(valid_messages)

                self.consumer.commit(
                    asynchronous=False
                )

                print(f"Committed {len(valid_messages)} messages")

            except Exception as e:

                print("Kafka Consumer Error:", e)

                await asyncio.sleep(2)

    async def shutdown(self):

        print("Stopping Kafka Consumer...")

        self.running = False

        # flush remaining messages
        await self.flush()

        if self.consumer:
            self.consumer.close()


kafka_consumer_service = KafkaConsumerService()