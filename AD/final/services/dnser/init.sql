CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
SELECT uuid_generate_v4();

CREATE TABLE IF NOT EXISTS users (
    id     SERIAL PRIMARY KEY,
    name   VARCHAR(32),
    passwd VARCHAR(32),
    money  INT DEFAULT 1000,
    token  UUID DEFAULT uuid_generate_v4()
);

CREATE TABLE IF NOT EXISTS addresses (
    id       SERIAL PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    ip       VARCHAR(64) NOT NULL,
    CONSTRAINT fk_users FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS domains (
    id       SERIAL PRIMARY KEY,
    ip_id    INTEGER NOT NULL,
    name     VARCHAR(32), -- flag here
    CONSTRAINT fk_addresses FOREIGN KEY(ip_id) REFERENCES addresses(id)
);