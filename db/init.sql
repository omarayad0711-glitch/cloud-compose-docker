-- NYXIE OS // C2 MYSQL SCHEMA
-- Lock = TRUE  -> compte actif
-- Lock = FALSE -> compte bloqué

CREATE DATABASE IF NOT EXISTS Authentification;
USE Authentification;

CREATE TABLE IF NOT EXISTS Account (
  Id       INT AUTO_INCREMENT PRIMARY KEY,
  Login    VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(64) NOT NULL,   -- SHA-256
  `Lock`   BOOLEAN NOT NULL DEFAULT TRUE
);

-- compteur séparé pour garder Account conforme à l'énoncé
CREATE TABLE IF NOT EXISTS FailedAttempts (
  Login    VARCHAR(50) PRIMARY KEY,
  Attempts INT NOT NULL DEFAULT 0
);

INSERT INTO Account (Login, password, `Lock`) VALUES
  ('admin', SHA2('admin123', 256), TRUE),
  ('dock',  SHA2('dock123', 256),  TRUE);
