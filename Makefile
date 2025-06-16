run:
	@go run .

db_down:
	@goose postgres "user=joaootaviocano dbname=murdock sslmode=disable" down
db_up:
	@goose postgres "user=joaootaviocano dbname=murdock sslmode=disable" up 
db_reset:
	@goose postgres "user=joaootaviocano dbname=murdock sslmode=disable" reset