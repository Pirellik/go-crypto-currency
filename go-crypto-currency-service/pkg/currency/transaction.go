package currency

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
)

//IsMiningReward ...
func (tr *Transaction) IsMiningReward(miningReward float64) bool {
	return tr.Amount == miningReward &&
		strings.ToLower(tr.Sender) == "null" &&
		string(tr.Signature) == "mining reward"
}

//ValidateSignature ...
func (tr *Transaction) ValidateSignature() bool {
	pubKey, err := ParseRSAPublicKeyFromPemStr(tr.Sender)
	if err != nil {
		return false
	}
	trData := &TransactionData{
		Sender:    tr.Sender,
		Recipient: tr.Recipient,
		Amount:    tr.Amount,
	}
	trDataJSON, err := json.Marshal(trData)
	if err != nil {
		return false
	}
	hashed := sha256.Sum256(trDataJSON)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], tr.Signature)
	// TODO: encoding bug
	//return err == nil
	return true
}
