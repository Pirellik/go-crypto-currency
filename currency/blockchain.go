package currency

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

//RegisterTransaction registers a transaction in our blockchain
func (b *BlockChain) RegisterTransaction(transaction Transaction) bool {
	transaction.SenderName = strings.ToLower(transaction.SenderName)
	transaction.RecipientName = strings.ToLower(transaction.RecipientName)
	transaction.SenderSign = strings.ToLower(transaction.SenderSign)
	b.PendingTransactions = append(b.PendingTransactions, transaction)
	return true
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
	for inputFmt != "0000" {
		nonce = nonce + 1
		hash := b.HashBlock(previousBlockHash, currentBlockData, nonce)
		inputFmt = hash[0:4]
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

		if blockHash[0:4] != "0000" {
			return false
		}

		if currentBlock.PreviousHash != prevBlock.Hash {
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
