CREATE TABLE users (
    uuid VARCHAR(36) PRIMARY KEY,
    password VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP NOT NULL
);

CREATE TABLE balances (
    user_uuid VARCHAR(36) PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
    rub DOUBLE PRECISION NOT NULL,
    ham DOUBLE PRECISION NOT NULL,
    vcn DOUBLE PRECISION NOT NULL,
    timestamp TIMESTAMP NOT NULL
);

CREATE TABLE kopilkas (
    uuid VARCHAR(36) PRIMARY KEY,
    owner_uuid VARCHAR(36) NOT NULL,
    title TEXT,
    goal TEXT,
    description TEXT,
    current_balance DOUBLE PRECISION,
    timestamp TIMESTAMP NOT NULL
);

CREATE TABLE kopilkaMembers (
    vault_uuid VARCHAR(36) REFERENCES kopilkas(uuid) ON DELETE CASCADE,
    user_uuid VARCHAR(36) REFERENCES users(uuid) ON DELETE CASCADE,
    deposit DOUBLE PRECISION,
    timestamp TIMESTAMP NOT NULL
);

ALTER TABLE users ALTER COLUMN timestamp SET DEFAULT now();
ALTER TABLE balances ALTER COLUMN timestamp SET DEFAULT now();
ALTER TABLE kopilkas ALTER COLUMN timestamp SET DEFAULT now();
ALTER TABLE kopilkaMembers ALTER COLUMN timestamp SET DEFAULT now();
