-- +goose Up
CREATE TABLE test (
    name VARCHAR(50)
);

-- +goose Down
DROP TABLE test;