package currency

import (
	"encoding/json"
)

//Transaction ..
type Transaction struct {
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
	Signature []byte  `json:"signature"`
}

//Block ...
type Block struct {
	Index        int           `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Nonce        int           `json:"nonce"`
	Hash         string        `json:"hash"`
	PreviousHash string        `json:"previoushash"`
}

//BlockChain ...
type BlockChain struct {
	Chain               []Block       `json:"chain"`
	PendingTransactions []Transaction `json:"pending_transactions"`
	NetworkNodes        []string      `json:"network_nodes"`
	MiningRewardAmount  float64       `json:"mining_reward"`
}

//BlockData ...
type BlockData struct {
	Index        string
	Transactions []Transaction
}

//TransactionData ...
type TransactionData struct {
	Sender    string  `json:"sender"`
	Recipient string  `json:"recipient"`
	Amount    float64 `json:"amount"`
}

//RSAKeyPair ...
type RSAKeyPair struct {
	Nickname   string `json:"nickname"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func (t *Transaction) UnmarshalJSON(data []byte) error {
	var s struct {
		Sender    string  `json:"sender"`
		Recipient string  `json:"recipient"`
		Amount    float64 `json:"amount"`
		Signature string  `json:"signature"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*t = Transaction{
		Sender:    s.Sender,
		Recipient: s.Recipient,
		Amount:    s.Amount,
		Signature: []byte(s.Signature),
	}
	return nil
}
