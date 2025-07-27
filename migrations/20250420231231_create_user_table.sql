-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    encryptedPassword CHAR(64) NOT NULL,
    salt CHAR(26) NOT NULL
);

-- +goose Down
DROP TABLE users;