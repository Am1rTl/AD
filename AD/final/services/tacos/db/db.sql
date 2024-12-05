CREATE TABLE users (
    userid        SERIAL        PRIMARY KEY,
    username      VARCHAR(64)   NOT NULL,
    password      VARCHAR(64)   NOT NULL
);

CREATE TABLE notes (
    noteid        SERIAL        PRIMARY KEY,
    data          VARCHAR(256)  NOT NULL,
    ownerid       INT           NOT NULL,
    timestamp     TIMESTAMP     NOT NULL
);

CREATE TABLE players (
    userid        SERIAL        PRIMARY KEY,
    name          VARCHAR(64)   NOT NULL,
    score         INT           NOT NULL,
    timestamp     TIMESTAMP     NOT NULL
);

ALTER TABLE notes ALTER COLUMN timestamp SET DEFAULT now();
ALTER TABLE players ALTER COLUMN timestamp SET DEFAULT now();