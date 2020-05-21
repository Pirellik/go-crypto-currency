package currency

import (
	"go-crypto-currency/logger"
	"net/http"

	"github.com/gorilla/mux"
)

var controller = &Controller{
	blockchain: &BlockChain{
		Chain:               []Block{},
		PendingTransactions: []Transaction{},
		NetworkNodes:        []string{},
		MiningReward:        1}}

// Route defines a route
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

var routes = []Route{
	Route{
		"Index",
		"GET",
		"/",
		controller.Index,
	},
	Route{
		"GetBlockchain",
		"GET",
		"/blockchain",
		controller.GetBlockchain,
	},
	Route{
		"GetAllBlockchainData",
		"GET",
		"/allBlockchainData",
		controller.GetAllBlockchainData,
	},
	Route{
		"GetNetworkNodes",
		"GET",
		"/networkNodes",
		controller.GetNetworkNodes,
	},
	Route{
		"GetBlockByBlockId",
		"GET",
		"/blockchain/{blockId}",
		controller.GetBlockByBlockID,
	},
	Route{
		"GetTransactionsByBlockId",
		"GET",
		"/blockchain/{blockId}/transactions",
		controller.GetTransactionsByBlockID,
	},
	Route{
		"GetBalanceByPublicKeyNickname",
		"GET",
		"/balance/{nickname}",
		controller.GetBalanceByPublicKeyNickname,
	},
	Route{
		"GetBalanceByPublicKey",
		"POST",
		"/balance",
		controller.GetBalanceByPublicKey,
	},
	Route{
		"GetPendingTransactions",
		"GET",
		"/pendingTransactions",
		controller.GetPendingTransactions,
	},
	Route{
		"GenerateRsaKeyPair",
		"POST",
		"/newRsaKeyPair/{nickname}",
		controller.GenerateRsaKeyPair,
	},
	Route{
		"GetRsaKeyPairs",
		"GET",
		"/rsaKeyPairs",
		controller.GetRsaKeyPairs,
	},
	Route{
		"DeleteRsaKeyPair",
		"DELETE",
		"/deleteRsaKeyPair/{nickname}",
		controller.DeleteRsaKeyPair,
	},
	Route{
		"RegisterNodeInExistingNetwork",
		"POST",
		"/registerNodeInExistingNetwork",
		controller.RegisterNodeInExistingNetwork,
	},
	Route{
		"RegisterAndBroadcastNode",
		"POST",
		"/register-and-broadcast-node",
		controller.RegisterAndBroadcastNode,
	},
	Route{
		"RegisterNode",
		"POST",
		"/register-node",
		controller.RegisterNode,
	},
	Route{
		"RegisterNodesBulk",
		"POST",
		"/register-nodes-bulk",
		controller.RegisterNodesBulk,
	},
	Route{
		"RegisterTransaction",
		"POST",
		"/transaction",
		controller.RegisterTransaction,
	},
	Route{
		"RegisterAndBroadcastTransaction",
		"POST",
		"/transaction/broadcast",
		controller.RegisterAndBroadcastTransaction,
	},
	Route{
		"MineWithPublicKey",
		"POST",
		"/mine",
		controller.MineWithPublicKey,
	},
	Route{
		"Mine",
		"GET",
		"/mine/{keyNickname}",
		controller.Mine,
	},
	Route{
		"ReceiveNewBlock",
		"POST",
		"/receive-new-block",
		controller.ReceiveNewBlock,
	},
	Route{
		"Consensus",
		"GET",
		"/consensus",
		controller.Consensus,
	},
}

//NewRouter configures a new router to the API
func NewRouter(nodeAddress string) *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	controller.currentNodeURL = "http://localhost:" + nodeAddress

	// create Genesis block
	controller.blockchain.CreateNewBlock(100, "0", "0")

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = logger.Logger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)

	}
	return router
}
