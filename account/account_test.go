package account

import (
	"encoding/hex"
	"fmt"
	"testing"
)

const privateKey = "0658ae5ce14eceacc235416e253645987dd95116d820d626767d48de77551cb0"

func TestCreateAccount(t *testing.T) {
	prikey, _ := hex.DecodeString(privateKey)
	newAccount := creatAccount(prikey)
	getEthAddress := newAccount.GetEthAddress()
	getBtcAddress := newAccount.GetBtcAddress()
	fmt.Println("getEthAddress:", getEthAddress)
	fmt.Println("getBtcAddress:", getBtcAddress)
}

func TestGetPublicKey(t *testing.T) {
	prikey, _ := hex.DecodeString(privateKey)
	newAccount := creatAccount(prikey)
	fmt.Println("publicKey", hex.EncodeToString(newAccount.PublicKey))
}
