-- +goose Up
CREATE TYPE usr_status AS ENUM('locked', 'pending', 'active');

CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    encryptedPassword CHAR(64) NOT NULL,
    salt CHAR(26) NOT NULL,
	status usr_status NOT NULL
);

-- +goose Down
DROP TABLE users;
DROP TYPE usr_status;
