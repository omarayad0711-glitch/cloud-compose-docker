"""C3 : consommateur RabbitMQ -> MongoDB.

Reçoit les événements de fraude publiés par C1, les enregistre dans la
collection `fraud_attempts` de MongoDB (C4), puis acquitte le message.
"""

import json
import os
import time

import pika
from pymongo import MongoClient

RABBIT_HOST = os.getenv("RABBIT_HOST", "rabbitmq")
RABBIT_QUEUE = os.getenv("RABBIT_QUEUE", "fraud_events")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
MONGO_DB = os.getenv("MONGO_DB", "fraud")

mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
collection = mongo[MONGO_DB]["fraud_attempts"]


def handle_message(channel, method, properties, body) -> None:
    """Enregistre un événement de fraude puis acquitte le message."""
    try:
        event = json.loads(body)
        collection.insert_one(event)
        print(f"[C3] Fraude tracée dans MongoDB: {event}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except json.JSONDecodeError as exc:
        print(f"[C3] Message JSON invalide ignoré: {exc}", flush=True)
        channel.basic_ack(delivery_tag=method.delivery_tag)
    except Exception as exc:  # noqa: BLE001
        print(f"[C3] Erreur, message remis dans la file: {exc}", flush=True)
        time.sleep(2)
        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)


def main() -> None:
    """Boucle de consommation avec reconnexion automatique."""
    while True:
        try:
            connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=RABBIT_HOST),
            )
            channel = connection.channel()
            channel.queue_declare(queue=RABBIT_QUEUE, durable=True)
            channel.basic_qos(prefetch_count=1)
            channel.basic_consume(
                queue=RABBIT_QUEUE,
                on_message_callback=handle_message,
                auto_ack=False,
            )
            print(
                f"[C3] En attente de messages sur '{RABBIT_QUEUE}'...",
                flush=True,
            )
            channel.start_consuming()
        except KeyboardInterrupt:
            print("[C3] Arrêt demandé.", flush=True)
            break
        except pika.exceptions.AMQPConnectionError as exc:
            print(
                f"[C3] RabbitMQ inaccessible ({exc}), "
                "nouvelle tentative dans 3s...",
                flush=True,
            )
            time.sleep(3)


if __name__ == "__main__":
    main()
