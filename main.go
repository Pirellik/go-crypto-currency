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

	allowedOrigins := handlers.AllowedOrigins([]string{"*"})
	allowedMethods := handlers.AllowedMethods([]string{"GET", "POST"})

	// launch server
	log.Fatal(http.ListenAndServe(":"+address,
		handlers.CORS(allowedOrigins, allowedMethods)(router)))
}
