package account

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
	"log"
)

const accountVersion = byte(0x00)            // 钱包版本
const compressedPublicKeyPrefix = byte(0x02) //压缩公钥前缀
const addressChecksumLen = 4                 // 验证码长度

type Account struct {
	PrivateKey []byte
	PublicKey  []byte
}

func creatAccount(privKey []byte) *Account {
	key, err := crypto.HexToECDSA(hex.EncodeToString(privKey))
	if err != nil {
		fmt.Errorf("privateKey Failed to generate a publicKey using HexToECDSA")
		return nil
	}
	pubKey := append(key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()...)
	account := Account{privKey, pubKey}
	return &account
}

func (a Account) GetEthAddress() string {
	pubHash := ethHashPubKey(a.PublicKey)
	address := hex.EncodeToString(pubHash[len(pubHash)-20:])
	return address
}

func ethHashPubKey(pubKey []byte) []byte {
	pubKeccak256 := crypto.Keccak256(pubKey)
	return pubKeccak256
}

func (a Account) GetBtcAddress() string {
	pubRIPEMD160 := btcHashPubKey(a.PublicKey)

	accountVersionedPayload := append([]byte{accountVersion}, pubRIPEMD160...)

	checksum := checksum(accountVersionedPayload)

	fullPayload := append(accountVersionedPayload, checksum...)

	// 进行 base58 编码，生成可视化地址
	address := base58.Encode(fullPayload)

	// 比特币地址格式：【钱包版本 + 公钥哈希 + 验证码】
	return address
}

func btcHashPubKey(pubKey []byte) []byte {
	pubKeySha256 := sha256.Sum256(append([]byte{compressedPublicKeyPrefix}, pubKey[:32]...))
	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(pubKeySha256[:])
	if err != nil {
		log.Panic(err)
	}
	// 获取ripemd160结果
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// 通过【钱包版本+公钥哈希】生成验证码
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:addressChecksumLen]
}
