import json
from confluent_kafka import Producer


class KafkaClient:
    def __init__(self, brokers: str):
        self.producer = Producer({
            "bootstrap.servers": brokers,
            "acks": "all"
        })

    def send(self, topic: str, data: dict):
        self.producer.produce(
            topic=topic,
            value=json.dumps(data).encode("utf-8")
        )
        self.producer.poll(0)

    def flush(self):
        self.producer.flush()


if __name__ == "__main__":
    producer = KafkaClient('80.225.239.163:9092')

    for i in range(10):
        producer.send(
            topic="agent-events",
            data={"id": i, "name": "producer data"}
        )

    producer.flush()

    