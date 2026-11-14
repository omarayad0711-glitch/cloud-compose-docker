# Auth Docker

Petite application d'authentification avec Docker Compose.

## Services

- **C1 — auth_app** : page de login (http://localhost:5000), bloque le compte après 3 échecs.
- **C2 — auth_mysql** : comptes et compteur de tentatives.
- **RabbitMQ** : file de messages (http://localhost:15672, guest / guest).
- **C3 — auth_fraud_logger** : lit les messages et enregistre les fraudes dans MongoDB.
- **C4 — auth_mongo** : stocke les fraudes.
- **C5 — auth_fraud_reporter** : recherche et affiche les rapports (http://localhost:5001).

## Lancer

```bash
docker compose up --build
```

Comptes de test : `admin` / `admin123` et `dock` / `dock123`.

## Tester

1. Se tromper 2 fois de mot de passe : le compte n'est pas encore bloqué.
2. Se tromper une 3e fois : le compte est bloqué et la fraude est enregistrée.
3. Ouvrir http://localhost:5001, chercher `dock` : le rapport s'affiche.

## Vérifier

```bash
docker exec -it auth_mysql mysql -uroot -prootpass Authentification -e "SELECT Login, \`Lock\` FROM Account;"
docker logs auth_fraud_logger
docker exec -it auth_mongo mongosh fraud --eval "db.fraud_attempts.find().pretty()"
```

## Débloquer un compte

```bash
docker exec -it auth_mysql mysql -uroot -prootpass Authentification -e "UPDATE Account SET \`Lock\`=TRUE WHERE Login='dock'; DELETE FROM FailedAttempts;"
```

## Tout réinitialiser

```bash
docker compose down -v
```
