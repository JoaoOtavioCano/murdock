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
