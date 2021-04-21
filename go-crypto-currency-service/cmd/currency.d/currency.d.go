package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Pirellik/go-crypto-currency/go-crypto-currency-service/internal/controller"
	"github.com/gorilla/handlers"
)

func main() {
	address := os.Getenv("SERVICE_PORT")
	hostname := os.Getenv("HOST_NAME")
	router := controller.NewRouter("http://" + hostname + ":" + address)

	allowedHeaders := handlers.AllowedHeaders([]string{"Accept", "Accept-Language", "Content-Type", "Content-Language", "Origin"})
	allowedOrigins := handlers.AllowedOrigins([]string{"*"})
	allowedMethods := handlers.AllowedMethods([]string{"GET", "POST", "OPTIONS", "PUT", "DELETE"})

	// launch server
	log.Fatal(http.ListenAndServe(":"+address,
		handlers.CORS(allowedOrigins, allowedMethods, allowedHeaders)(router)))
}
