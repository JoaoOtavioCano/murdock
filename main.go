package main

import (
	"log"
	"os"

	"github.com/JoaoOtavioCano/murdock/adapters/database/postgres"
	httpadapter "github.com/JoaoOtavioCano/murdock/adapters/httpAdapter"
	"github.com/JoaoOtavioCano/murdock/application"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatal(err)
	}
	pepper := os.Getenv("PEPPER")
	jwtSecret := os.Getenv("JWT_SECRET")
	port := os.Getenv("PORT")

	db, err := postgres.NewDatabase()
	if err != nil {
		log.Fatalf("Database error: %v", err)
	}
	lt := application.NewLoginThrottler(db)
	authService := application.NewAuthService(db, lt, jwtSecret, pepper)
	server := httpadapter.NewHTTPServer(port, authService)

	server.Start()
}
