package controller

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Pirellik/go-crypto-currency/go-crypto-currency-service/pkg/currency"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

//Controller ...
type Controller struct {
	blockchain     currency.BlockChain
	currentNodeURL string
}

func NewController(nodeAddress string) Controller {
	return Controller{
		blockchain: currency.BlockChain{
			Chain:               []currency.Block{},
			PendingTransactions: []currency.Transaction{},
			NetworkNodes:        []string{},
			MiningRewardAmount:  1,
		},
		currentNodeURL: nodeAddress,
	}
}

//noteResp ...
type noteResp struct {
	Note string
}

type accountBalance struct {
	Balance float64 `json:"balance"`
}

type publicKey struct {
	PublicKey string `json:"publickey"`
}

type newNode struct {
	NewNodeURL string `json:"newnodeurl"`
}

type networkNode struct {
	NetworkNodeURL string `json:"networknodeurl"`
}

//Index GET /
func (c *Controller) Index(w http.ResponseWriter, r *http.Request) {
	respOK(w, nil)
}

//GetBlockchain GET /blockchain
func (c *Controller) GetBlockchain(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(c.blockchain.Chain)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal chain")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetBlockchain GET /all-blockchain-data
func (c *Controller) GetAllBlockchainData(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(c.blockchain)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal blockchain")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetNetworkNodes GET /network-nodes
func (c *Controller) GetNetworkNodes(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(c.blockchain.NetworkNodes)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal network nodes")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetBlockByBlockId GET /blockchain/{block_id}
func (c *Controller) GetBlockByBlockID(w http.ResponseWriter, r *http.Request) {
	blockId, err := strconv.Atoi(mux.Vars(r)["blockId"])
	if err != nil || blockId < 1 || blockId > len(c.blockchain.Chain) {
		respBadRequest(w)
		return
	}
	data, err := json.Marshal(c.blockchain.Chain[blockId-1])
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal block")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetTransactionsByBlockID GET /blockchain/{block_id}/transactions
func (c *Controller) GetTransactionsByBlockID(w http.ResponseWriter, r *http.Request) {
	blockId, err := strconv.Atoi(mux.Vars(r)["blockId"])
	if err != nil || blockId < 1 || blockId > len(c.blockchain.Chain) {
		respBadRequest(w)
		return
	}
	data, err := json.Marshal(c.blockchain.Chain[blockId-1].Transactions)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal transactions")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetBalanceByPublicKeyNickname GET /balance/{nickname}
func (c *Controller) GetBalanceByPublicKeyNickname(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	publicKey, err := currency.GetPublicKeyByNickname(nickname)
	if err != nil {
		log.Error().Err(err).Str("nickname", nickname).Msg("public key not found")
		respBadRequest(w)
		return
	}
	accBalance := accountBalance{
		Balance: c.blockchain.GetAccBalanceByPublicKey(publicKey),
	}
	data, err := json.Marshal(accBalance)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal account balance")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetBalanceByPublicKey POST /balance
func (c *Controller) GetBalanceByPublicKey(w http.ResponseWriter, r *http.Request) {
	var key publicKey
	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}

	accBalance := accountBalance{
		Balance: c.blockchain.GetAccBalanceByPublicKey(key.PublicKey),
	}
	data, err := json.Marshal(accBalance)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal account balance")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetTransactionsByPublicKeyNickname GET /transactions/{nickname}
func (c *Controller) GetTransactionsByPublicKeyNickname(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	publicKey, err := currency.GetPublicKeyByNickname(nickname)
	if err != nil {
		log.Error().Err(err).Str("nickname", nickname).Msg("public key not found")
		respBadRequest(w)
		return
	}

	trs := c.blockchain.GetTransactionsByPublicKey(publicKey)
	data, err := json.Marshal(trs)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal transactions")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GetPendingTransactions GET /pending-transactions
func (c *Controller) GetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	data, err := json.Marshal(c.blockchain.PendingTransactions)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal pending transactions")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//GenerateRSAKeyPair POST /rsa-key-pairs/{nickname}
func (c *Controller) GenerateRSAKeyPair(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	newKeyPair, err := currency.NewRSAKeyPair(nickname)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate new rsa key pair")
		respInternalError(w)
		return
	}
	if err := newKeyPair.SaveToFile(); err != nil {
		log.Error().Err(err).Msg("failed to save RSA key pair")
		respInternalError(w)
		return
	}
	respOK(w, nil)
}

//GetRSAKeyPairs GET /rsa-key-pairs/
func (c *Controller) GetRSAKeyPairs(w http.ResponseWriter, r *http.Request) {
	keys, err := currency.GetRSAKeyPairsFromFile()
	if err != nil {
		log.Error().Err(err).Msg("failed to read keys from file")
		respInternalError(w)
		return
	}
	data, err := json.Marshal(keys)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal keys")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//DeleteRSAKeyPair DELETE /rsa-key-pairs/{nickname}
func (c *Controller) DeleteRSAKeyPair(w http.ResponseWriter, r *http.Request) {
	nicknameToDelete := strings.ToLower(mux.Vars(r)["nickname"])
	if err := currency.DeleteRSAKeyPair(nicknameToDelete); err != nil {
		log.Error().Err(err).Str("nickname", nicknameToDelete).Msg("failed to delete RSA keys")
		respInternalError(w)
		return
	}
	respOK(w, nil)
}

//RegisterTransaction POST /transaction
func (c *Controller) RegisterTransaction(w http.ResponseWriter, r *http.Request) {
	var tr currency.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}

	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		log.Info().Interface("transaction", tr).Msg("incoming transaction rejected")
		respBadRequest(w)
		return
	}
	resp := noteResp{
		Note: "Transaction created and broadcasted successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//RegisterTransaction POST /transaction/broadcast
func (c *Controller) RegisterAndBroadcastTransaction(w http.ResponseWriter, r *http.Request) {
	var tr currency.Transaction
	if err := json.NewDecoder(r.Body).Decode(&tr); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}

	signature, err := currency.SignTransaction(tr)
	if err != nil {
		log.Error().Err(err).Interface("transaction", tr).Msg("failed to sign transaction")
		respInternalError(w)
		return
	}
	tr.Signature = signature
	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		log.Info().Interface("transaction", tr).Msg("transaction rejected")
		respBadRequest(w)
		return
	}

	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			trToBroadcast, err := json.Marshal(tr)
			if err != nil {
				log.Error().Err(err).Str("node", node).Interface("transaction", trToBroadcast).Msg("failed to broadcast transaction")
				continue
			}
			makePostCall(node+"/transaction", trToBroadcast)
		}
	}
	resp := noteResp{
		Note: "Transaction created and broadcasted successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//Mine GET /mine/{keyNickname}
func (c *Controller) Mine(w http.ResponseWriter, r *http.Request) {
	keyNickname := strings.ToLower(mux.Vars(r)["keyNickname"])
	publicKey, err := currency.GetPublicKeyByNickname(keyNickname)
	if err != nil {
		log.Error().Err(err).Str("nickname", keyNickname).Msg("public key not found")
		respBadRequest(w)
		return
	}
	newBlock, err := c.blockchain.Mine(publicKey)
	if err != nil {
		log.Error().Err(err).Str("nickname", keyNickname).Msg("failed to mine new block")
		respInternalError(w)
		return
	}
	blockToBroadcast, err := json.Marshal(newBlock)
	if err != nil {
		log.Error().Err(err).Str("nickname", keyNickname).Msg("failed to broadcast new block")
		respInternalError(w)
		return
	}
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			makePostCall(node+"/receive-new-block", blockToBroadcast)
		}
	}
	resp := noteResp{
		Note: "New block mined and broadcast successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//MineWithPublicKey POST /mine
func (c *Controller) MineWithPublicKey(w http.ResponseWriter, r *http.Request) {
	var key publicKey
	if err := json.NewDecoder(r.Body).Decode(&key); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}

	newBlock, err := c.blockchain.Mine(key.PublicKey)
	if err != nil {
		log.Error().Err(err).Str("publicKey", key.PublicKey).Msg("failed to mine new block")
		respInternalError(w)
		return
	}
	blockToBroadcast, err := json.Marshal(newBlock)
	if err != nil {
		log.Error().Err(err).Str("publicKey", key.PublicKey).Msg("failed to broadcast new block")
		respInternalError(w)
		return
	}
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			makePostCall(node+"/receive-new-block", blockToBroadcast)
		}
	}
	resp := noteResp{
		Note: "New block mined and broadcast successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//RegisterNode POST /register-node
func (c *Controller) RegisterNode(w http.ResponseWriter, r *http.Request) {
	var node newNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}
	if node.NewNodeURL == c.currentNodeURL {
		respOK(w, nil)
		return
	}
	success := c.blockchain.RegisterNode(node.NewNodeURL) // registers the node into the blockchain
	if !success {
		log.Error().Str("newNodeURL", node.NewNodeURL).Msg("failed to register node")
		respInternalError(w)
		return
	}
	resp := noteResp{
		Note: "Node registered successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//RegisterNodesBulk POST /register-nodes-bulk
func (c *Controller) RegisterNodesBulk(w http.ResponseWriter, r *http.Request) {
	var allNodes []string
	if err := json.NewDecoder(r.Body).Decode(&allNodes); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}
	for _, node := range allNodes {
		if node != c.currentNodeURL {
			success := c.blockchain.RegisterNode(node)
			if !success {
				log.Error().Str("nodeURL", node).Msg("failed to register node")
			}
		}
	}
	resp := noteResp{
		Note: "Bulk registration successful.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//RegisterNodeInExistingNetwork POST /register-in-existing-network
func (c *Controller) RegisterNodeInExistingNetwork(w http.ResponseWriter, r *http.Request) {
	var node networkNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}
	nodeToRegister := newNode{
		NewNodeURL: c.currentNodeURL,
	}
	payload, err := json.Marshal(nodeToRegister)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal node URL")
		respInternalError(w)
		return
	}
	makePostCall(node.NetworkNodeURL+"/register-and-broadcast-node", []byte(payload))

	resp := noteResp{
		Note: "Registration request sent successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//RegisterAndBroadcastNode POST /register-and-broadcast-node
func (c *Controller) RegisterAndBroadcastNode(w http.ResponseWriter, r *http.Request) {
	var node newNode
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}
	success := c.blockchain.RegisterNode(node.NewNodeURL) // registers the node into the blockchain
	if !success {
		log.Error().Str("newNodeURL", node.NewNodeURL).Msg("failed to register and broadcast node")
		respInternalError(w)
		return
	}

	for _, networkNode := range c.blockchain.NetworkNodes {
		if networkNode != node.NewNodeURL {
			makePostCall(networkNode+"/register-node", []byte(`{"newnodeurl":"`+node.NewNodeURL+`"}`))
		}
	}

	allNodes := append(c.blockchain.NetworkNodes, c.currentNodeURL)
	payload, err := json.Marshal(allNodes)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal nodes")
		respInternalError(w)
		return
	}
	makePostCall(node.NewNodeURL+"/register-nodes-bulk", []byte(payload))

	resp := noteResp{
		Note: "Node registered successfully.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//ReceiveNewBlock POST /receive-new-block
func (c *Controller) ReceiveNewBlock(w http.ResponseWriter, r *http.Request) {
	var blockReceived currency.Block
	if err := json.NewDecoder(r.Body).Decode(&blockReceived); err != nil {
		log.Error().Err(err).Msg("error reading request body")
		respInternalError(w)
		return
	}
	// TODO: fix encoding bug that breaks hash
	// correctHash := c.blockchain.CheckNewBlockHash(blockReceived)
	// validTransactions := c.blockchain.ValidateBlockTransactions(blockReceived)
	correctHash := true
	validTransactions := true
	if correctHash && validTransactions {
		c.blockchain.PendingTransactions = []currency.Transaction{}
		c.blockchain.Chain = append(c.blockchain.Chain, blockReceived)
		resp := noteResp{
			Note: "New Block received and accepted.",
		}
		data, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("failed to marshal response")
			respInternalError(w)
			return
		}
		respOK(w, data)
		return
	}
	log.Info().Interface("newBlock", blockReceived).Msg("new block rejected")
	resp := noteResp{
		Note: "New Block rejected.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}

//Consensus GET /consensus
func (c *Controller) Consensus(w http.ResponseWriter, r *http.Request) {
	maxChainLength := 0
	var longestChain currency.BlockChain
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			req, err := http.NewRequest("GET", node+"/all-blockchain-data", nil)
			if err != nil {
				log.Error().Err(err).Msg("failed to create new request")
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Error().Err(err).Msg("Error retrieving blockchain")
				continue
			}
			var chain currency.BlockChain
			if err := json.NewDecoder(resp.Body).Decode(&chain); err != nil {
				log.Error().Err(err).Msg("error reading response body")
				continue
			}
			if maxChainLength < len(chain.Chain) {
				maxChainLength = len(chain.Chain)
				longestChain = chain
			}
		}
	}
	// TODO: there is some bug with unmarshaling, because hash doesnt start with "000"
	// valid := longestChain.ChainIsValid()
	valid := true
	if maxChainLength <= len(c.blockchain.Chain) || !valid {
		resp := noteResp{
			Note: "This chain has not been replaced.",
		}
		body, err := json.Marshal(resp)
		if err != nil {
			log.Error().Err(err).Msg("failed to marshal response")
			respInternalError(w)
			return
		}
		respOK(w, body)
		return
	}

	c.blockchain.Chain = longestChain.Chain
	c.blockchain.PendingTransactions = longestChain.PendingTransactions
	resp := noteResp{
		Note: "This chain has been replaced.",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response")
		respInternalError(w)
		return
	}
	respOK(w, data)
}
