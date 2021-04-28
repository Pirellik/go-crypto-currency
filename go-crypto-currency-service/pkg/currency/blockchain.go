package currency

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	miningDifficulty string = "000"
)

func (b *BlockChain) Mine(publicKey string) (*Block, error) {
	lastBlock := b.GetLastBlock()
	previousBlockHash := lastBlock.Hash
	tr := Transaction{
		Sender:    "NULL",
		Recipient: publicKey,
		Amount:    1,
		Signature: []byte("mining reward"),
	}
	success := b.RegisterTransaction(tr)
	if !success {
		return nil, errors.New("failed to register mining reward transfer")
	}
	currentBlockData := BlockData{Index: strconv.Itoa(lastBlock.Index - 1), Transactions: b.PendingTransactions}
	currentBlockDataAsByteArray, err := json.Marshal(currentBlockData)
	if err != nil {
		return nil, err
	}
	currentBlockDataAsStr := base64.URLEncoding.EncodeToString(currentBlockDataAsByteArray)
	nonce := b.ProofOfWork(previousBlockHash, currentBlockDataAsStr)
	blockHash := b.HashBlock(previousBlockHash, currentBlockDataAsStr, nonce)
	newBlock := b.CreateNewBlock(nonce, previousBlockHash, blockHash)
	return &newBlock, nil
}

//RegisterTransaction registers a transaction in our blockchain
func (b *BlockChain) RegisterTransaction(transaction Transaction) bool {
	if b.ValidateTransactionBeforeRegistering(transaction) {
		b.PendingTransactions = append(b.PendingTransactions, transaction)
		return true
	}
	return false
}

//ValidateTransactionBeforeRegistering validates a transaction
func (b *BlockChain) ValidateTransactionBeforeRegistering(transaction Transaction) bool {
	if transaction.IsMiningReward(b.MiningRewardAmount) {
		return true
	}
	return b.GetAccBalanceByPublicKey(transaction.Sender) >= transaction.Amount && transaction.ValidateSignature()
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
		PreviousHash: previousHash,
	}

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
			}
			if transaction.Recipient == publicKey {
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
	_, err := h.Write([]byte(strToHash))
	if err != nil {
		log.Error().Err(err).Msg("failed to hash a block - unable to write data to a stream")
		return ""
	}
	hashed := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hashed
}

//ProofOfWork ...
func (b *BlockChain) ProofOfWork(previousBlockHash string, currentBlockData string) int {
	nonce := -1
	inputFmt := ""
	for inputFmt != miningDifficulty {
		nonce = nonce + 1
		hash := b.HashBlock(previousBlockHash, currentBlockData, nonce)
		inputFmt = hash[0:len(miningDifficulty)]
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

//ValidateBlockTransactions ...
func (b *BlockChain) ValidateBlockTransactions(newBlock Block) bool {
	containsExactlyOneMiningReward := b.ContainsExactlyOneMiningReward(newBlock.Transactions)
	amountsCorrect := b.ValidateTransactionsByTheirAmount(newBlock.Transactions)
	allSigned := b.ValidateTransactionSignatures(newBlock.Transactions)
	return containsExactlyOneMiningReward && amountsCorrect && allSigned
}

//ContainsExactlyOneMiningReward ...
func (b *BlockChain) ContainsExactlyOneMiningReward(trs []Transaction) bool {
	miningRewards := 0
	for _, tr := range trs {
		if tr.IsMiningReward(b.MiningRewardAmount) {
			miningRewards++
		}
	}
	return miningRewards == 1
}

//ValidateTransactionSignatures: TODO
func (b *BlockChain) ValidateTransactionSignatures(trs []Transaction) bool {
	return true
}

//ValidateTransactionsByTheirAmount ...
func (b *BlockChain) ValidateTransactionsByTheirAmount(trs []Transaction) bool {
	for _, tr := range trs {
		if tr.IsMiningReward(b.MiningRewardAmount) {
			continue
		}
		if b.GetAccBalanceByPublicKey(tr.Sender) < tr.Amount {
			return false
		}
	}
	return true
}

//ChainIsValid Used by consensus algorithm
func (b *BlockChain) ChainIsValid() bool {
	i := 1
	for i < len(b.Chain) {
		currentBlock := b.Chain[i]
		prevBlock := b.Chain[i-1]
		currentBlockData := BlockData{
			Index:        strconv.Itoa(prevBlock.Index - 1),
			Transactions: currentBlock.Transactions,
		}
		currentBlockDataAsByteArray, err := json.Marshal(currentBlockData)
		if err != nil {
			log.Error().Err(err).Msg("failed to marshal block data")
			return false
		}
		blockHash := b.HashBlock(prevBlock.Hash, string(currentBlockDataAsByteArray), currentBlock.Nonce)
		if blockHash[0:len(miningDifficulty)] != miningDifficulty {
			log.Info().Str("blockHash", blockHash).Msg("incorrect hash")
			return false
		}
		if currentBlock.PreviousHash != prevBlock.Hash {
			log.Info().Msg("invalid previous block hash")
			return false
		}
		i = i + 1
	}

	genesisBlock := b.Chain[0]
	correctNonce := genesisBlock.Nonce == 100
	correctPreviousHash := genesisBlock.PreviousHash == "0"
	correctHash := genesisBlock.Hash == "0"
	correctTransactions := len(genesisBlock.Transactions) == 0

	return (correctNonce && correctPreviousHash && correctHash && correctTransactions)
}
