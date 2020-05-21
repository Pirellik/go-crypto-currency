package main

import (
	"go-crypto-currency/currency"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
)

func main() {
	address := os.Args[1]
	router := currency.NewRouter(address)

	allowedHeaders := handlers.AllowedHeaders([]string{"Accept", "Accept-Language", "Content-Type", "Content-Language", "Origin"})
	allowedOrigins := handlers.AllowedOrigins([]string{"*"})
	allowedMethods := handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS", "PUT", "DELETE"})

	// launch server
	log.Fatal(http.ListenAndServe(":"+address,
		handlers.CORS(allowedOrigins, allowedMethods, allowedHeaders)(router)))
}
