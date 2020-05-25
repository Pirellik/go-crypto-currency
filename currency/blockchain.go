package currency

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

//RegisterTransaction registers a transaction in our blockchain
func (b *BlockChain) RegisterTransaction(transaction Transaction) bool {
	if b.ValidateTransactionBeforeRegistering(transaction) {
		b.PendingTransactions = append(b.PendingTransactions, transaction)
		return true
	} else {
		return false
	}
}

//SignTransaction registers a transaction in our blockchain
func (b *BlockChain) SignTransaction(transaction Transaction) []byte {
	var keys []RsaKeyPair
	if fileExists("key_pairs/keys.json") {
		keys_from_file, _ := ioutil.ReadFile("key_pairs/keys.json")
		_ = json.Unmarshal(keys_from_file, &keys)
	}

	var privKey *rsa.PrivateKey
	var err error
	for _, keypair := range keys {
		if keypair.PublicKey == transaction.Sender {
			privKey, err = b.ParseRsaPrivateKeyFromPemStr(keypair.PrivateKey)
		}
	}

	trData := &TransactionData{Sender: transaction.Sender, Recipient: transaction.Recipient, Amount: transaction.Amount}
	trDataJSON, err := json.Marshal(trData)
	if err != nil {
		fmt.Println(err)
		return []byte("failed to sign")
	}
	hashed := sha256.Sum256(trDataJSON)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		panic(err)
	}
	return signature
}

//GetPublicKeyByNickname ...
func (b *BlockChain) GetPublicKeyByNickname(nickname string) string {
	var keys []RsaKeyPair
	if fileExists("key_pairs/keys.json") {
		keysFromFile, _ := ioutil.ReadFile("key_pairs/keys.json")
		_ = json.Unmarshal(keysFromFile, &keys)
	}

	for _, keypair := range keys {
		if keypair.Nickname == nickname {
			return keypair.PublicKey
		}
	}
	return ""
}

//ValidateTransactionBeforeRegistering validates a transaction
func (b *BlockChain) ValidateTransactionBeforeRegistering(transaction Transaction) bool {
	if b.IsMiningReward(transaction) {
		return true
	} else if b.GetAccBalanceByPublicKey(transaction.Sender) >= transaction.Amount && b.ValidateSignature(transaction) {
		return true
	} else {
		fmt.Println("Invalid transaction")
		return false
	}
}

//ValidateSignature ...
func (b *BlockChain) ValidateSignature(tr Transaction) bool {
	pubKey, err := b.ParseRsaPublicKeyFromPemStr(tr.Sender)
	fmt.Println("PASKO ERROR", err)

	trData := &TransactionData{Sender: tr.Sender, Recipient: tr.Recipient, Amount: tr.Amount}
	trDataJSON, _ := json.Marshal(trData)
	hashed := sha256.Sum256(trDataJSON)
	fmt.Println("SIGNATURE AS BYTES", tr.Signature)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], tr.Signature)
	fmt.Println("PASKO final ERR", err)
	if err == nil {
		return true
	} else {
		return false
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

//RegisterNode registers a node in our blockchain
func (b *BlockChain) RegisterNode(node string) bool {
	if !contains(b.NetworkNodes, node) {
		b.NetworkNodes = append(b.NetworkNodes, node)
	}
	return true
}

//CreateNewBlock ...
func (b *BlockChain) CreateNewBlock(nonce int, previousHash string, hash string) Block {
	newBlock := Block{
		Index:        len(b.Chain) + 1,
		Transactions: b.PendingTransactions,
		Timestamp:    time.Now().UnixNano(),
		Nonce:        nonce,
		Hash:         hash,
		PreviousHash: previousHash}

	b.PendingTransactions = []Transaction{}
	b.Chain = append(b.Chain, newBlock)
	return newBlock
}

//GetLastBlock ...
func (b *BlockChain) GetLastBlock() Block {
	return b.Chain[len(b.Chain)-1]
}

//GetAccBalanceByPublicKey ...
func (b *BlockChain) GetAccBalanceByPublicKey(publicKey string) float64 {
	balance := 0.0
	for _, block := range b.Chain {
		for _, transaction := range block.Transactions {
			if transaction.Sender == publicKey {
				balance = balance - transaction.Amount
			} else if transaction.Recipient == publicKey {
				balance = balance + transaction.Amount
			}
		}
	}
	return balance
}

//GetTransactionsByPublicKey ...
func (b *BlockChain) GetTransactionsByPublicKey(publicKey string) []Transaction {
	var trs []Transaction
	for _, block := range b.Chain {
		for _, transaction := range block.Transactions {
			if transaction.Sender == publicKey || transaction.Recipient == publicKey {
				trs = append(trs, transaction)
			}
		}
	}
	return trs
}

//HashBlock ...
func (b *BlockChain) HashBlock(previousHash string, currentBlockData string, nonce int) string {
	h := sha256.New()
	strToHash := previousHash + currentBlockData + strconv.Itoa(nonce)
	h.Write([]byte(strToHash))
	hashed := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hashed
}

//ProofOfWork ...
func (b *BlockChain) ProofOfWork(previousBlockHash string, currentBlockData string) int {
	nonce := -1
	inputFmt := ""
	for inputFmt != "000" {
		nonce = nonce + 1
		hash := b.HashBlock(previousBlockHash, currentBlockData, nonce)
		inputFmt = hash[0:3]
	}
	return nonce
}

//CheckNewBlockHash ...
func (b *BlockChain) CheckNewBlockHash(newBlock Block) bool {
	lastBlock := b.GetLastBlock()
	correctHash := lastBlock.Hash == newBlock.PreviousHash
	correctIndex := (lastBlock.Index + 1) == newBlock.Index

	return (correctHash && correctIndex)
}

func (b *BlockChain) GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return privkey, &privkey.PublicKey
}

func (b *BlockChain) ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func (b *BlockChain) ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (b *BlockChain) ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)

	return string(pubkey_pem), nil
}

func (b *BlockChain) ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

//ValidateBlockTransactions ...
func (b *BlockChain) ValidateBlockTransactions(newBlock Block) bool {
	containsExactlyOneMiningReward := b.ContainsExactlyOneMiningReward(newBlock.Transactions)
	amountsCorrect := b.ValidateTransactionsByTheirAmount(newBlock.Transactions)
	allSigned := b.ValidateTransactionSignatures(newBlock.Transactions)
	fmt.Println("PASKO containsExactlyOneMiningReward", containsExactlyOneMiningReward)
	fmt.Println("PASKO amountsCorrect", amountsCorrect)
	fmt.Println("PASKO allSigned", allSigned)
	return containsExactlyOneMiningReward && amountsCorrect && allSigned
}

//ContainsExactlyOneMiningReward ...
func (b *BlockChain) ContainsExactlyOneMiningReward(trs []Transaction) bool {
	miningRewards := 0
	for _, tr := range trs {
		if b.IsMiningReward(tr) {
			miningRewards++
		}
	}
	if miningRewards == 1 {
		return true
	} else {
		return false
	}
}

//IsMiningReward ...
func (b *BlockChain) IsMiningReward(tr Transaction) bool {
	if tr.Amount == b.MiningReward &&
		strings.ToLower(tr.Sender) == "null" &&
		string(tr.Signature) == "mining reward" {
		return true
	} else {
		return false
	}
}

//ValidateTransactionSignatures ...
func (b *BlockChain) ValidateTransactionSignatures(trs []Transaction) bool {
	return true
}

//ValidateTransactionsByTheirAmount ...
func (b *BlockChain) ValidateTransactionsByTheirAmount(trs []Transaction) bool {
	for _, tr := range trs {
		if b.IsMiningReward(tr) {
			continue
		} else if !b.IsBalanceGreaterThanAmount(tr) {
			return false
		}
	}
	return true
}

//IsBalanceGreaterThanAmount ...
func (b *BlockChain) IsBalanceGreaterThanAmount(tr Transaction) bool {
	fmt.Println("b.GetAccBalanceByPublicKey(strings.ToLower(tr.Sender))", b.GetAccBalanceByPublicKey(tr.Sender))
	fmt.Println("tr.Amount", tr.Amount)
	if b.GetAccBalanceByPublicKey(tr.Sender) >= tr.Amount {
		return true
	} else {
		return false
	}
}

//ChainIsValid Used by consensus algorithm
func (b *BlockChain) ChainIsValid() bool {
	i := 1
	for i < len(b.Chain) {
		currentBlock := b.Chain[i]
		prevBlock := b.Chain[i-1]
		currentBlockData := BlockData{Index: strconv.Itoa(prevBlock.Index - 1), Transactions: currentBlock.Transactions}
		currentBlockDataAsByteArray, _ := json.Marshal(currentBlockData)
		currentBlockDataAsStr := base64.URLEncoding.EncodeToString(currentBlockDataAsByteArray)
		blockHash := b.HashBlock(prevBlock.Hash, currentBlockDataAsStr, currentBlock.Nonce)
		if blockHash[0:3] != "000" {
			fmt.Println("DUPA")
			return false
		}

		if currentBlock.PreviousHash != prevBlock.Hash {
			fmt.Println("DUPA")
			return false
		}

		i = i + 1
	}

	genesisBlock := b.Chain[0]
	correctNonce := genesisBlock.Nonce == 100
	correctPreviousHash := genesisBlock.PreviousHash == "0"
	correctHash := genesisBlock.Hash == "0"
	correctBets := len(genesisBlock.Transactions) == 0

	return (correctNonce && correctPreviousHash && correctHash && correctBets)
}
