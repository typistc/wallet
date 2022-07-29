package signature

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

const privateKey = "0658ae5ce14eceacc235416e253645987dd95116d820d626767d48de77551cb0"
const publicKey = "67f28579f93610ad3ea0d7a954c3995ec0747baea513dc5817f0198b9eb531dece5db094e2274ad57e380bcacc49468afb49ffc49ec1fbad0d1b153ed3fc01a2"
const sign = "7cabc0cf101041a294580ac656f93671e375142ba7ab3b617ec785e421f15d954c4c93d22cf7c770b80fa722c870c2683cebb6ed1854f3295d738e3034caeaf401"

func TestDecompressPubkey(t *testing.T) {
	compressedPubKeyPrefix := byte(0x02)
	pubKey, _ := hex.DecodeString(publicKey)
	decompressPubKey := append([]byte{compressedPubKeyPrefix}, pubKey[:32]...)
	uncompressedPubKey, _ := DecompressPubkey(decompressPubKey)
	//decompressKey := CompressPubkey(uncompressedPubKey)
	fmt.Println("uncompressedPubKey:", hex.EncodeToString(append(uncompressedPubKey.X.Bytes(), uncompressedPubKey.Y.Bytes()...)))
}

func TestCompressPubkey(t *testing.T) {
	key, _ := crypto.HexToECDSA(privateKey)
	decompressKey := CompressPubkey(&key.PublicKey)
	fmt.Println("decompressKey:", hex.EncodeToString(decompressKey))
}

func TestSign(t *testing.T) {
	key, _ := crypto.HexToECDSA(privateKey)
	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)
	signature, _ := crypto.Sign(hash.Bytes(), key)
	fmt.Println("signature:", hex.EncodeToString(signature)) // 7cabc0cf101041a294580ac656f93671e375142ba7ab3b617ec785e421f15d954c4c93d22cf7c770b80fa722c870c2683cebb6ed1854f3295d738e3034caeaf401
}

func TestVerifySignature(t *testing.T) {
	key, _ := crypto.HexToECDSA(privateKey)
	decompressKey := CompressPubkey(&key.PublicKey)
	//decompressKey := CompressPubkey(&key.PublicKey)
	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)
	signature, _ := hex.DecodeString(sign)
	// signature[:len(signature)-1] 删除	signature 末尾的V v一般为0或1
	result := crypto.VerifySignature(decompressKey, hash.Bytes(), signature[:len(signature)-1])
	fmt.Println("result:", result)
}
