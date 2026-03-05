-- +goose Up
CREATE TYPE code_type AS ENUM('createAccount', 'updateEmail', 'updatePassword' );

CREATE TABLE confirmation_codes (
	code CHAR(7) NOT NULL,
	expireAt TIMESTAMP WITH TIME ZONE NOT NULL,
	userID UUID NOT NULL,
	digitalAddr VARCHAR(50) NOT NULL,
	codeType code_type NOT NULL,
	data VARCHAR(50),

    FOREIGN KEY (userID) REFERENCES users (id),
    PRIMARY KEY (code, digitalAddr)
);

-- +goose Down
DROP TABLE confirmation_codes;
