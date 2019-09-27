CREATE TABLE users (
       id          SERIAL        PRIMARY KEY,
       username    VARCHAR(128)  NOT NULL UNIQUE,
       salt_base64 VARCHAR(48)   NOT NULL,
       argon2_hash VARCHAR(256)  NOT NULL);
