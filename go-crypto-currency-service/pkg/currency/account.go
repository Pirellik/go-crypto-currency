package currency

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"github.com/Pirellik/go-crypto-currency/go-crypto-currency-service/pkg/utils"
)

const (
	keysFilePath string = "key_pairs/keys.json"
)

var (
	errKeysFileNotPresent  error = errors.New("keys file not present")
	errParseFailed         error = errors.New("failed to parse PEM block containing the key")
	errPublicKeyNotFound   error = errors.New("public key not found")
	errPrivateKeyNotFound  error = errors.New("proper private key not found")
	errInvalidPublicKeyStr error = errors.New("Key type is not RSA")
)

func NewRSAKeyPair(nickname string) (*RSAKeyPair, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	priv_pem := exportRsaPrivateKeyAsPemStr(privkey)
	pub_pem, err := exportRsaPublicKeyAsPemStr(&privkey.PublicKey)
	if err != nil {
		return nil, err
	}

	ret := &RSAKeyPair{
		Nickname:   nickname,
		PrivateKey: priv_pem,
		PublicKey:  pub_pem,
	}
	return ret, nil
}

func (kp *RSAKeyPair) SaveToFile() error {
	var keys []RSAKeyPair
	if !utils.CheckIfFileExists(keysFilePath) {
		return errKeysFileNotPresent
	}
	keys_from_file, err := ioutil.ReadFile(keysFilePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(keys_from_file, &keys); err != nil {
		return err
	}
	keys = append(keys, *kp)
	file, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(keysFilePath, file, 0644); err != nil {
		return err
	}
	return nil
}

func GetRSAKeyPairsFromFile() ([]RSAKeyPair, error) {
	if !utils.CheckIfFileExists(keysFilePath) {
		return nil, errKeysFileNotPresent
	}
	keysFile, err := os.ReadFile(keysFilePath)
	if err != nil {
		return nil, err
	}
	var keys []RSAKeyPair
	if err := json.Unmarshal(keysFile, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

//GetPublicKeyByNickname ...
func GetPublicKeyByNickname(nickname string) (string, error) {
	if !utils.CheckIfFileExists(keysFilePath) {
		return "", errKeysFileNotPresent
	}
	keysFromFile, err := os.ReadFile(keysFilePath)
	if err != nil {
		return "", err
	}
	var keys []RSAKeyPair
	if err := json.Unmarshal(keysFromFile, &keys); err != nil {
		return "", err
	}

	for _, keypair := range keys {
		if keypair.Nickname == nickname {
			return keypair.PublicKey, nil
		}
	}
	return "", errPublicKeyNotFound
}

func DeleteRSAKeyPair(nickname string) error {
	if !utils.CheckIfFileExists(keysFilePath) {
		return errKeysFileNotPresent
	}
	keys_from_file, err := os.ReadFile(keysFilePath)
	if err != nil {
		return err
	}
	var keys []RSAKeyPair
	if err := json.Unmarshal(keys_from_file, &keys); err != nil {
		return err
	}
	for index, pair := range keys {
		if pair.Nickname == nickname {
			keys = removeKeysAtIndex(keys, index)
			break
		}
	}
	file, err := json.MarshalIndent(keys, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(keysFilePath, file, 0644)
}

//SignTransaction generate signature for a transaction using proper key
func SignTransaction(transaction Transaction) ([]byte, error) {
	if !utils.CheckIfFileExists(keysFilePath) {
		return nil, errKeysFileNotPresent
	}
	keys_from_file, err := os.ReadFile(keysFilePath)
	if err != nil {
		return nil, err
	}
	var keys []RSAKeyPair
	if err := json.Unmarshal(keys_from_file, &keys); err != nil {
		return nil, err
	}

	privKeyStr := ""
	for _, keypair := range keys {
		if keypair.PublicKey == transaction.Sender {
			privKeyStr = keypair.PrivateKey
			break
		}
	}
	if privKeyStr == "" {
		return nil, errPrivateKeyNotFound
	}
	privKey, err := ParseRSAPrivateKeyFromPemStr(privKeyStr)
	if err != nil {
		return nil, err
	}

	trData := &TransactionData{
		Sender:    transaction.Sender,
		Recipient: transaction.Recipient,
		Amount:    transaction.Amount,
	}
	trDataJSON, err := json.Marshal(trData)
	if err != nil {
		return nil, err
	}
	hashed := sha256.Sum256(trDataJSON)

	return rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
}

func removeKeysAtIndex(s []RSAKeyPair, index int) []RSAKeyPair {
	s[len(s)-1], s[index] = s[index], s[len(s)-1]
	return s[:len(s)-1]
}

func exportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
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

func ParseRSAPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errParseFailed
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ParseRSAPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errParseFailed
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break
	}
	return nil, errInvalidPublicKeyStr
}
