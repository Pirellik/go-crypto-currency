package controller

import (
	"net/http"

	"github.com/Pirellik/go-crypto-currency/go-crypto-currency-service/pkg/logger"

	"github.com/gorilla/mux"
)

// Route defines a route
type Route struct {
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

func getRoutes(controller *Controller) []Route {
	return []Route{
		{
			"GET",
			"/",
			controller.Index,
		},
		{
			"GET",
			"/blockchain",
			controller.GetBlockchain,
		},
		{
			"GET",
			"/allBlockchainData",
			controller.GetAllBlockchainData,
		},
		{
			"GET",
			"/networkNodes",
			controller.GetNetworkNodes,
		},
		{
			"GET",
			"/blockchain/{blockId}",
			controller.GetBlockByBlockID,
		},
		{
			"GET",
			"/blockchain/{blockId}/transactions",
			controller.GetTransactionsByBlockID,
		},
		{
			"GET",
			"/balance/{nickname}",
			controller.GetBalanceByPublicKeyNickname,
		},
		{
			"POST",
			"/balance",
			controller.GetBalanceByPublicKey,
		},
		{
			"GET",
			"/transactions/{nickname}",
			controller.GetTransactionsByPublicKeyNickname,
		},
		{
			"GET",
			"/pendingTransactions",
			controller.GetPendingTransactions,
		},
		{
			"POST",
			"/newRsaKeyPair/{nickname}",
			controller.GenerateRSAKeyPair,
		},
		{
			"GET",
			"/rsaKeyPairs",
			controller.GetRSAKeyPairs,
		},
		{
			"DELETE",
			"/deleteRsaKeyPair/{nickname}",
			controller.DeleteRSAKeyPair,
		},
		{
			"POST",
			"/registerNodeInExistingNetwork",
			controller.RegisterNodeInExistingNetwork,
		},
		{
			"POST",
			"/register-and-broadcast-node",
			controller.RegisterAndBroadcastNode,
		},
		{
			"POST",
			"/register-node",
			controller.RegisterNode,
		},
		{
			"POST",
			"/register-nodes-bulk",
			controller.RegisterNodesBulk,
		},
		{
			"POST",
			"/transaction",
			controller.RegisterTransaction,
		},
		{
			"POST",
			"/transaction/broadcast",
			controller.RegisterAndBroadcastTransaction,
		},
		{
			"POST",
			"/mine",
			controller.MineWithPublicKey,
		},
		{
			"GET",
			"/mine/{keyNickname}",
			controller.Mine,
		},
		{
			"POST",
			"/receive-new-block",
			controller.ReceiveNewBlock,
		},
		{
			"GET",
			"/consensus",
			controller.Consensus,
		},
	}
}

//NewRouter configures a new router to the API
func NewRouter(nodeAddress string) *mux.Router {
	controller := NewController(nodeAddress)
	routes := getRoutes(&controller)
	router := mux.NewRouter().StrictSlash(true)

	// create Genesis block
	controller.blockchain.CreateNewBlock(100, "0", "0")

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = logger.LoggingInterceptor(handler)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Handler(handler)

	}
	return router
}
