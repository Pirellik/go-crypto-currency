package currency

//Transaction ..
type Transaction struct {
	SenderName    string  `json:"sendername"`
	RecipientName string  `json:"recipientname"`
	Amount        float64 `json:"amount"`
	SenderSign    string  `json:"sendersign"`
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
}

//BlockData ...
type BlockData struct {
	Index        string
	Transactions []Transaction
}
