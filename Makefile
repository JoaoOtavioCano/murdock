run:
	@go run .

db_down:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" down
db_up:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" up 
db_reset:
	@goose -dir ./migrations/ postgres "user=joaootaviocano dbname=murdock sslmode=disable" reset
