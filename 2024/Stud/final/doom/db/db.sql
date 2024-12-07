CREATE TABLE IF NOT EXISTS users (
       userid              SERIAL        PRIMARY KEY,
       username            VARCHAR(256)  NOT NULL,
       password            VARCHAR(256)  NOT NULL,
       bio              VARCHAR(256)  NOT NULL
);

CREATE TABLE IF NOT EXISTS scoreboard (
       userid              INT           NOT NULL,
       mapid               INT           NOT NULL,
       score               INT           NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
       maps                INT           NOT NULL
);

INSERT INTO settings(maps) VALUES (3);
INSERT INTO users(username, password, bio) VALUES ('test', 'test', 'bio');
