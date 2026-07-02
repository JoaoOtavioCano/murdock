run:
	@go run .

test:
	@go test -count=1 ./...

db_down:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" down
db_up:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" up 
db_reset:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" reset

docker_build:
	docker build -t murdock .

docker_run: docker_build
	docker run -it --rm --name murdock murdock

compose_build:
	docker compose build

compose_up: compose_build
	docker compose up

compose_down:
	docker compose down
