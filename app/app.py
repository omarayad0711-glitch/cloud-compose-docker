"""C1 : application d'authentification Flask.

Affiche la page de login, vérifie les identifiants dans MySQL (C2),
bloque le compte à la troisième tentative échouée, puis publie un
événement de fraude dans RabbitMQ à destination de C3.
"""

import datetime
import json
import os
import time

import mysql.connector
import pika
from flask import Flask, render_template, request

MAX_ATTEMPTS = 3

DB_HOST = os.getenv("DB_HOST", "db")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "rootpass")
DB_NAME = os.getenv("DB_NAME", "Authentification")

RABBIT_HOST = os.getenv("RABBIT_HOST", "rabbitmq")
RABBIT_QUEUE = os.getenv("RABBIT_QUEUE", "fraud_events")

app = Flask(__name__)


def get_db(retries: int = 20, delay: int = 2):
    """Attend que MySQL soit prêt puis renvoie une connexion."""
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            return mysql.connector.connect(
                host=DB_HOST,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
            )
        except mysql.connector.Error as exc:
            last_error = exc
            print(
                f"[C1] MySQL indisponible ({attempt}/{retries}): {exc}",
                flush=True,
            )
            time.sleep(delay)

    raise RuntimeError(f"Base de données inaccessible: {last_error}")


def publish_fraud_event(login: str, attempts: int, ip: str | None) -> None:
    """Publie un événement de fraude (C1 -> RabbitMQ -> C3).

    Une erreur RabbitMQ ne doit jamais casser le login.
    """
    event = {
        "login": login,
        "attempts": attempts,
        "ip": ip,
        "reason": f"Compte bloqué après {attempts} tentatives échouées",
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc,
        ).isoformat(),
    }

    connection = None
    try:
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=RABBIT_HOST),
        )
        channel = connection.channel()
        channel.queue_declare(queue=RABBIT_QUEUE, durable=True)
        channel.basic_publish(
            exchange="",
            routing_key=RABBIT_QUEUE,
            body=json.dumps(event),
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type="application/json",
            ),
        )
        print(f"[C1] Message envoyé à RabbitMQ: {event}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[C1] Publication RabbitMQ échouée: {exc}", flush=True)
    finally:
        if connection is not None and connection.is_open:
            connection.close()


def _check_password(cursor, password: str, password_hash: str) -> bool:
    """Compare le mot de passe fourni à son hash SHA-256 stocké."""
    cursor.execute("SELECT SHA2(%s, 256) AS hash", (password,))
    return cursor.fetchone()["hash"] == password_hash


def _record_failed_attempt(cursor, login: str) -> int:
    """Incrémente le compteur d'échecs et renvoie sa nouvelle valeur."""
    cursor.execute(
        "INSERT INTO FailedAttempts (Login, Attempts) VALUES (%s, 1) "
        "ON DUPLICATE KEY UPDATE Attempts = Attempts + 1",
        (login,),
    )
    cursor.execute(
        "SELECT Attempts FROM FailedAttempts WHERE Login = %s",
        (login,),
    )
    return cursor.fetchone()["Attempts"]


def _reset_failed_attempts(cursor, login: str) -> None:
    """Remet le compteur d'échecs à zéro après une connexion réussie."""
    cursor.execute(
        "DELETE FROM FailedAttempts WHERE Login = %s",
        (login,),
    )


def _process_login(cursor, login: str, password: str, ip: str | None):
    """Vérifie les identifiants et applique la logique de blocage.

    Renvoie (message, ok, blocked_event). `blocked_event` vaut
    (login, attempts, ip) si le compte vient d'être bloqué.
    """
    cursor.execute(
        "SELECT Id, password, `Lock` FROM Account WHERE Login = %s",
        (login,),
    )
    account = cursor.fetchone()

    if account is None:
        return "Login ou mot de passe incorrect.", False, None

    if not account["Lock"]:
        return "Compte bloqué (Lock = false).", False, None

    if _check_password(cursor, password, account["password"]):
        _reset_failed_attempts(cursor, login)
        return "Welcome Dock…", True, None

    attempts = _record_failed_attempt(cursor, login)
    if attempts >= MAX_ATTEMPTS:
        cursor.execute(
            "UPDATE Account SET `Lock` = FALSE WHERE Login = %s",
            (login,),
        )
        message = "Compte bloqué après 3 tentatives (Lock = false)."
        return message, False, (login, attempts, ip)

    remaining = MAX_ATTEMPTS - attempts
    message = (
        "Login ou mot de passe incorrect. "
        f"Tentatives restantes : {remaining}"
    )
    return message, False, None


def authenticate(login: str, password: str, ip: str | None):
    """Ouvre une connexion, traite le login puis valide la transaction."""
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        message, ok, blocked_event = _process_login(cursor, login, password, ip)
        db.commit()  # le blocage est d'abord validé dans MySQL (C2)
        return message, ok, blocked_event
    finally:
        cursor.close()
        db.close()


@app.route("/", methods=["GET", "POST"])
def login_view():
    """Page de login : GET affiche le formulaire, POST vérifie le compte."""
    message = None
    ok = False

    if request.method == "POST":
        login = request.form.get("login", "").strip()
        password = request.form.get("password", "")

        message, ok, blocked_event = authenticate(
            login,
            password,
            request.remote_addr,
        )

        if blocked_event is not None:  # puis on prévient C3 via RabbitMQ
            publish_fraud_event(*blocked_event)

    return render_template("login.html", message=message, ok=ok)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
