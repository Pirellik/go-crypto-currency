package currency

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

//Controller ...
type Controller struct {
	blockchain     *BlockChain
	currentNodeURL string
}

//ResponseToSend ...
type ResponseToSend struct {
	Note string
}

//Index GET /
func (c *Controller) Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
}

//GetBlockchain GET /blockchain
func (c *Controller) GetBlockchain(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(c.blockchain.Chain)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetBlockchain GET /allBlockchainData
func (c *Controller) GetAllBlockchainData(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(c.blockchain)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetNetworkNodes GET /networkNodes
func (c *Controller) GetNetworkNodes(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(c.blockchain.NetworkNodes)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetBlockByBlockId GET /blockchain/{block_id}
func (c *Controller) GetBlockByBlockID(w http.ResponseWriter, r *http.Request) {
	blockId, err := strconv.Atoi(mux.Vars(r)["blockId"])
	if err != nil || blockId < 1 || blockId > len(c.blockchain.Chain) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(c.blockchain.Chain[blockId-1])
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetTransactionsByBlockID GET /blockchain/{block_id}/transactions
func (c *Controller) GetTransactionsByBlockID(w http.ResponseWriter, r *http.Request) {
	blockId, err := strconv.Atoi(mux.Vars(r)["blockId"])
	if err != nil || blockId < 1 || blockId > len(c.blockchain.Chain) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(c.blockchain.Chain[blockId-1].Transactions)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetBalanceByPublicKeyNickname GET /balance/{nickname}
func (c *Controller) GetBalanceByPublicKeyNickname(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	publicKey := c.blockchain.GetPublicKeyByNickname(nickname)
	var accBalance struct {
		Balance float64 `json:"balance"`
	}

	accBalance.Balance = c.blockchain.GetAccBalanceByPublicKey(publicKey)
	data, _ := json.Marshal(accBalance)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetBalanceByPublicKey POST /balance
func (c *Controller) GetBalanceByPublicKey(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error GetBalanceByPublicKey", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error GetBalanceByPublicKey", err)
	}
	var key struct {
		Public string `json:"publickey"`
	}
	if err := json.Unmarshal(body, &key); err != nil {
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error GetBalanceByPublicKey unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	var accBalance struct {
		Balance float64 `json:"balance"`
	}

	accBalance.Balance = c.blockchain.GetAccBalanceByPublicKey(key.Public)
	data, _ := json.Marshal(accBalance)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetTransactionsByPublicKeyNickname GET /transactions/{nickname}
func (c *Controller) GetTransactionsByPublicKeyNickname(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	publicKey := c.blockchain.GetPublicKeyByNickname(nickname)

	var trs []Transaction

	trs = c.blockchain.GetTransactionsByPublicKey(publicKey)
	data, _ := json.Marshal(trs)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

//GetPendingTransactions GET /pendingTransactions
func (c *Controller) GetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(c.blockchain.PendingTransactions)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

//GenerateRsaKeyPair POST /newRsaKeyPair/{nickname}
func (c *Controller) GenerateRsaKeyPair(w http.ResponseWriter, r *http.Request) {
	nickname := strings.ToLower(mux.Vars(r)["nickname"])
	// Create the keys
	priv, pub := c.blockchain.GenerateRsaKeyPair()

	// Export the keys to pem string
	priv_pem := c.blockchain.ExportRsaPrivateKeyAsPemStr(priv)
	pub_pem, _ := c.blockchain.ExportRsaPublicKeyAsPemStr(pub)

	var keys []RsaKeyPair
	if fileExists("key_pairs/keys.json") {
		keys_from_file, _ := ioutil.ReadFile("key_pairs/keys.json")
		_ = json.Unmarshal(keys_from_file, &keys)
	}

	keys = append(keys, RsaKeyPair{Nickname: nickname, PublicKey: pub_pem, PrivateKey: priv_pem})
	file, _ := json.MarshalIndent(keys, "", " ")
	_ = ioutil.WriteFile("key_pairs/keys.json", file, 0644)

}

//GetRsaKeyPairs GET /rsaKeyPairs/
func (c *Controller) GetRsaKeyPairs(w http.ResponseWriter, r *http.Request) {
	var keys []RsaKeyPair
	if fileExists("key_pairs/keys.json") {
		keys_from_file, _ := ioutil.ReadFile("key_pairs/keys.json")
		_ = json.Unmarshal(keys_from_file, &keys)
	}

	for _, keypair := range keys {
		// Import the keys from pem string
		priv_parsed, _ := c.blockchain.ParseRsaPrivateKeyFromPemStr(keypair.PrivateKey)
		pub_parsed, _ := c.blockchain.ParseRsaPublicKeyFromPemStr(keypair.PublicKey)

		// Export the newly imported keys
		priv_parsed_pem := c.blockchain.ExportRsaPrivateKeyAsPemStr(priv_parsed)
		pub_parsed_pem, _ := c.blockchain.ExportRsaPublicKeyAsPemStr(pub_parsed)

		// Check that the exported/imported keys match the original keys
		if keypair.PrivateKey != priv_parsed_pem || keypair.PublicKey != pub_parsed_pem {
			fmt.Println("Failure: Export and Import did not result in same Keys")
		} else {
			fmt.Println("Success")
		}
	}

	data, _ := json.Marshal(keys)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return
}

func remove(s []RsaKeyPair, i int) []RsaKeyPair {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

//DeleteRsaKeyPair DELETE /deleteRsaKeyPair/{nickname}
func (c *Controller) DeleteRsaKeyPair(w http.ResponseWriter, r *http.Request) {
	nicknameToDelete := strings.ToLower(mux.Vars(r)["nickname"])

	var keys []RsaKeyPair
	if fileExists("key_pairs/keys.json") {
		keys_from_file, _ := ioutil.ReadFile("key_pairs/keys.json")
		_ = json.Unmarshal(keys_from_file, &keys)
	}
	for index, pair := range keys {
		if pair.Nickname == nicknameToDelete {
			keys = remove(keys, index)
			break
		}
	}
	file, _ := json.MarshalIndent(keys, "", " ")
	_ = ioutil.WriteFile("key_pairs/keys.json", file, 0644)
}

//RegisterTransaction POST /transaction
func (c *Controller) RegisterTransaction(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error RegisterTransaction", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterTransaction", err)
	}
	var tr Transaction
	if err := json.Unmarshal(body, &tr); err != nil {
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterTransaction unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	fmt.Println("SIGNATURE AS BYTES AFTER RECEIVING", tr.Signature)

	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusConflict)
		var resp ResponseToSend
		resp.Note = "Transaction rejected."
		data, _ := json.Marshal(resp)
		w.Write(data)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	var resp ResponseToSend
	resp.Note = "Transaction created and broadcasted successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//RegisterTransaction POST /transaction/broadcast
func (c *Controller) RegisterAndBroadcastTransaction(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalln("Error RegisterAndBroadcastTransaction", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterAndBroadcastTransaction", err)
	}
	var tr Transaction
	if err := json.Unmarshal(body, &tr); err != nil {
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterAndBroadcastTransaction unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	tr.Signature = c.blockchain.SignTransaction(tr)
	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// broadcast
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			trToBroadcast, _ := json.Marshal(tr)
			fmt.Println("SIGNATURE AS BYTES BEFORE SEND", []byte(tr.Signature))
			MakePostCall(node+"/transaction", trToBroadcast)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	var resp ResponseToSend
	resp.Note = "Transaction created and broadcast successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
}

//Mine GET /mine/{keyNickname}
func (c *Controller) Mine(w http.ResponseWriter, r *http.Request) {
	keyNickname := strings.ToLower(mux.Vars(r)["keyNickname"])

	lastBlock := c.blockchain.GetLastBlock()
	previousBlockHash := lastBlock.Hash
	tr := Transaction{Sender: "NULL", Recipient: c.blockchain.GetPublicKeyByNickname(keyNickname), Amount: 1, Signature: []byte("mining reward")}
	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	currentBlockData := BlockData{Index: strconv.Itoa(lastBlock.Index - 1), Transactions: c.blockchain.PendingTransactions}
	currentBlockDataAsByteArray, _ := json.Marshal(currentBlockData)
	currentBlockDataAsStr := base64.URLEncoding.EncodeToString(currentBlockDataAsByteArray)
	nonce := c.blockchain.ProofOfWork(previousBlockHash, currentBlockDataAsStr)
	blockHash := c.blockchain.HashBlock(previousBlockHash, currentBlockDataAsStr, nonce)
	newBlock := c.blockchain.CreateNewBlock(nonce, previousBlockHash, blockHash)
	blockToBroadcast, _ := json.Marshal(newBlock)
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			// call /receive-new-block in node
			MakePostCall(node+"/receive-new-block", blockToBroadcast)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	var resp ResponseToSend
	resp.Note = "New block mined and broadcast successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//MineWithPublicKey POST /mine
func (c *Controller) MineWithPublicKey(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error GetBalanceByPublicKey", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error GetBalanceByPublicKey", err)
	}
	var key struct {
		Public string `json:"publickey"`
	}
	if err := json.Unmarshal(body, &key); err != nil {
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error GetBalanceByPublicKey unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	lastBlock := c.blockchain.GetLastBlock()
	previousBlockHash := lastBlock.Hash
	tr := Transaction{Sender: "NULL", Recipient: key.Public, Amount: 1, Signature: []byte("mining reward")}
	success := c.blockchain.RegisterTransaction(tr)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	currentBlockData := BlockData{Index: strconv.Itoa(lastBlock.Index - 1), Transactions: c.blockchain.PendingTransactions}
	currentBlockDataAsByteArray, _ := json.Marshal(currentBlockData)
	currentBlockDataAsStr := base64.URLEncoding.EncodeToString(currentBlockDataAsByteArray)
	nonce := c.blockchain.ProofOfWork(previousBlockHash, currentBlockDataAsStr)
	blockHash := c.blockchain.HashBlock(previousBlockHash, currentBlockDataAsStr, nonce)
	newBlock := c.blockchain.CreateNewBlock(nonce, previousBlockHash, blockHash)
	blockToBroadcast, _ := json.Marshal(newBlock)
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			// call /receive-new-block in node
			MakePostCall(node+"/receive-new-block", blockToBroadcast)
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	var resp ResponseToSend
	resp.Note = "New block mined and broadcast successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//RegisterNode POST /register-node
func (c *Controller) RegisterNode(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error RegisterNode", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterNode", err)
	}
	var node struct {
		NewNodeURL string `json:"newNodeUrl"`
	}
	if err := json.Unmarshal(body, &node); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterNode unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	var resp ResponseToSend
	if node.NewNodeURL != c.currentNodeURL {
		success := c.blockchain.RegisterNode(node.NewNodeURL) // registers the node into the blockchain
		if !success {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	resp.Note = "Node registered successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//RegisterNodesBulk POST /register-nodes-bulk
func (c *Controller) RegisterNodesBulk(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error RegisterNodesBulk", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterNodesBulk", err)
	}
	var allNodes []string
	if err := json.Unmarshal(body, &allNodes); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterNodesBulk unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	for _, node := range allNodes {
		if node != c.currentNodeURL {
			success := c.blockchain.RegisterNode(node) // registers the node into the blockchain
			if !success {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
	}
	var resp ResponseToSend
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	resp.Note = "Bulk registration successful."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//MakeCall ...
func MakeCall(mode string, url string, jsonStr []byte) interface{} {
	// call url in node
	log.Println(mode)
	log.Println(url)
	req, err := http.NewRequest(mode, url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error in call " + url)
		log.Println(err)
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	var returnValue interface{}
	if err := json.Unmarshal(respBody, &returnValue); err != nil { // unmarshal body contents as a type Candidate
		if err != nil {
			log.Fatalln("Error "+url+" unmarshalling data", err)
			return nil
		}
	}
	log.Println(returnValue)
	return returnValue
}

//MakePostCall ...
func MakePostCall(url string, jsonStr []byte) {
	// call url in POST
	MakeCall("POST", url, jsonStr)
}

//MakeGetCall ...
func MakeGetCall(url string, jsonStr []byte) interface{} {
	// call url in GET
	return MakeCall("GET", url, jsonStr)
}

//BroadcastNode broadcasting node
func BroadcastNode(newNode string, nodes []string) {
	for _, node := range nodes {
		if node != newNode {
			var registerNodesJSON = []byte(`{"newnodeurl":"` + newNode + `"}`)

			// call /register-node in node
			MakePostCall(node+"/register-node", registerNodesJSON)
		}
	}
}

//RegisterNodeInExistingNetwork POST /registerNodeInExistingNetwork
func (c *Controller) RegisterNodeInExistingNetwork(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error RegisterNodeInExistingNetwork", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterNodeInExistingNetwork", err)
	}
	var networkNode struct {
		NetworkNodeURL string `json:"networknodeurl"`
	}
	if err := json.Unmarshal(body, &networkNode); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterNodeInExistingNetwork unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	var nodeToRegister struct {
		Url string `json:"newnodeurl"`
	}

	nodeToRegister.Url = "http://" + r.Host

	payload, err := json.Marshal(nodeToRegister)
	registerJSON := []byte(payload)
	MakePostCall(networkNode.NetworkNodeURL+"/register-and-broadcast-node", registerJSON)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	var resp ResponseToSend
	resp.Note = "Registration request sent successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//RegisterAndBroadcastNode POST /register-and-broadcast-node
func (c *Controller) RegisterAndBroadcastNode(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error RegisterNode", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error RegisterNode", err)
	}
	var node struct {
		NewNodeURL string `json:"newnodeurl"`
	}
	if err := json.Unmarshal(body, &node); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error RegisterNode unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	var resp ResponseToSend
	success := c.blockchain.RegisterNode(node.NewNodeURL) // registers the node into the blockchain
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// broadcast
	BroadcastNode(node.NewNodeURL, c.blockchain.NetworkNodes)

	// register all nodes in new node
	allNodes := append(c.blockchain.NetworkNodes, c.currentNodeURL)
	payload, err := json.Marshal(allNodes)
	registerBulkJSON := []byte(payload)
	MakePostCall(node.NewNodeURL+"/register-nodes-bulk", registerBulkJSON)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	resp.Note = "Node registered successfully."
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//ReceiveNewBlock POST /receive-new-block
func (c *Controller) ReceiveNewBlock(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body) // read the body of the request
	if err != nil {
		log.Fatalln("Error ReceiveNewBlock", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := r.Body.Close(); err != nil {
		log.Fatalln("Error ReceiveNewBlock", err)
	}

	var blockReceived Block
	if err := json.Unmarshal(body, &blockReceived); err != nil { // unmarshall body contents as a type Candidate
		w.WriteHeader(422) // unprocessable entity
		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Fatalln("Error ReceiveNewBlock unmarshalling data", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	var resp ResponseToSend
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	fmt.Println("PASKO HASH CHECK", c.blockchain.CheckNewBlockHash(blockReceived))
	fmt.Println("PASKO TRANS CHECK", c.blockchain.ValidateBlockTransactions(blockReceived))

	// append block to blockchain
	if c.blockchain.CheckNewBlockHash(blockReceived) && c.blockchain.ValidateBlockTransactions(blockReceived) {
		resp.Note = "New Block received and accepted."
		c.blockchain.PendingTransactions = []Transaction{}
		c.blockchain.Chain = append(c.blockchain.Chain, blockReceived)
	} else {
		resp.Note = "New Block rejected."
	}

	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}

//Consensus GET /consensus
func (c *Controller) Consensus(w http.ResponseWriter, r *http.Request) {
	maxChainLength := 0
	var longestChain *BlockChain
	var resp ResponseToSend
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	for _, node := range c.blockchain.NetworkNodes {
		if node != c.currentNodeURL {
			// call /blockchain in node
			// call url in node
			req, err := http.NewRequest("GET", node+"/allBlockchainData", nil)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Println("Error retrieving blockchain")
				log.Println(err)
			}
			defer resp.Body.Close()
			respBody, err := ioutil.ReadAll(resp.Body)
			var chain *BlockChain
			if err := json.Unmarshal(respBody, &chain); err != nil { // unmarshal body contents as a type Candidate
				if err != nil {
					log.Fatalln("Error unmarshalling data", err)
				}
			}

			if chain != nil {
				chainLength := len(chain.Chain)
				if maxChainLength < chainLength {
					maxChainLength = chainLength
					longestChain = chain
				}
			}
		}
	}

	log.Println(longestChain.ChainIsValid())

	if maxChainLength > len(c.blockchain.Chain) && longestChain.ChainIsValid() {
		c.blockchain.Chain = longestChain.Chain
		c.blockchain.PendingTransactions = longestChain.PendingTransactions

		resp.Note = "This chain has been replaced."
	} else {
		resp.Note = "This chain has not been replaced."
	}

	w.WriteHeader(http.StatusOK)
	data, _ := json.Marshal(resp)
	w.Write(data)
	return
}
