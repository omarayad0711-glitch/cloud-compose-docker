"""C5 : service de consultation des rapports de fraude.

Permet à un utilisateur de rechercher un login et d'afficher, sous forme
de tableau, les tentatives de fraude enregistrées pour ce compte dans
MongoDB (C4). Les rapports sont produits quand un compte est verrouillé.
"""

import os
import re
from datetime import datetime

from flask import Flask, render_template, request
from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
MONGO_DB = os.getenv("MONGO_DB", "fraud")
MONGO_COLLECTION = os.getenv("MONGO_COLLECTION", "fraud_attempts")

app = Flask(__name__)
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
collection = client[MONGO_DB][MONGO_COLLECTION]


def _format_timestamp(value) -> str:
    """Formate un timestamp ISO pour l'affichage, avec repli brut."""
    if not value:
        return "—"
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return str(value)


def search_reports(login: str) -> list[dict]:
    """Cherche les événements de fraude liés à un login (insensible à la casse)."""
    if not login:
        return []

    query = {"login": {"$regex": f"^{re.escape(login)}$", "$options": "i"}}
    cursor = collection.find(query).sort("timestamp", -1).limit(100)
    return list(cursor)


def _to_rows(reports: list[dict]) -> list[dict]:
    """Transforme les documents MongoDB en lignes prêtes pour le template."""
    return [
        {
            "login": report.get("login", "—"),
            "attempts": report.get("attempts", "—"),
            "ip": report.get("ip") or "—",
            "reason": report.get("reason", "—"),
            "timestamp": _format_timestamp(report.get("timestamp")),
        }
        for report in reports
    ]


@app.route("/", methods=["GET", "POST"])
def index():
    """Recherche un login et affiche les rapports sous forme de tableau."""
    login = ""
    rows = []
    error = None

    if request.method == "POST":
        login = request.form.get("login", "").strip()
        try:
            rows = _to_rows(search_reports(login))
        except PyMongoError as exc:
            error = f"Base de rapports indisponible: {exc}"

    return render_template(
        "report.html",
        login=login,
        rows=rows,
        error=error,
        searched=request.method == "POST",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
