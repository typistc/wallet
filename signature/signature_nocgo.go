package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"

	btc_ecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

//SignatureLength indicates the byte length required to carry a signature with recovery id.
// SignatureLength 表示携带带有recovery id的签名所需的字节长度。
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
// RecoveryIDOffset 指向包含恢复 id 的签名中的字节偏移量。
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
// DigestLength 设置签名摘要的确切长度
const DigestLength = 32

// Ecrecover returns the uncompressed public key that created the given signature.
// Ecrecover 返回创建给定签名的未压缩公钥。
func Ecrecover(hash, sig []byte) ([]byte, error) {
	pub, err := sigToPub(hash, sig)
	if err != nil {
		return nil, err
	}
	bytes := pub.SerializeUncompressed()
	return bytes, err
}

func sigToPub(hash, sig []byte) (*btcec.PublicKey, error) {
	if len(sig) != SignatureLength {
		return nil, errors.New("invalid signature")
	}
	// Convert to btcec input format with 'recovery id' v at the beginning.
	// 转换为开头带有“recovery id”v 的 btcec 输入格式。
	btcsig := make([]byte, SignatureLength)
	btcsig[0] = sig[RecoveryIDOffset] + 27
	copy(btcsig[1:], sig)

	pub, _, err := btc_ecdsa.RecoverCompact(btcsig, hash)
	return pub, err
}

// SigToPub returns the public key that created the given signature.
func SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	pub, err := sigToPub(hash, sig)
	if err != nil {
		return nil, err
	}
	return pub.ToECDSA(), nil
}

// Sign calculates an ECDSA signature.
// Sign 计算 ECDSA 签名。
//
// This function is susceptible to chosen plaintext attacks that can leak
// information about the private key that is used for signing. Callers must
// be aware that the given hash cannot be chosen by an adversary. Common
// solution is to hash any input before calculating the signature.
// 此功能容易受到选择的明文攻击，这些攻击可能会泄露有关用于签名的私钥的信息。
// 调用者必须知道给定的哈希不能被对手选择。常见的解决方案是在计算签名之前对任何输入进行哈希处理。
//
// The produced signature is in the [R || S || V] format where V is 0 or 1.
func Sign(hash []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	if prv.Curve != btcec.S256() {
		return nil, fmt.Errorf("private key curve is not secp256k1")
	}
	// ecdsa.PrivateKey -> btcec.PrivateKey
	var priv btcec.PrivateKey
	if overflow := priv.Key.SetByteSlice(prv.D.Bytes()); overflow || priv.Key.IsZero() {
		return nil, fmt.Errorf("invalid private key")
	}
	defer priv.Zero()
	sig, err := btc_ecdsa.SignCompact(&priv, hash, false) // ref uncompressed pubkey
	if err != nil {
		return nil, err
	}
	// Convert to Ethereum signature format with 'recovery id' v at the end.
	// 转换为最后带有“recovery id”v 的以太坊签名格式。
	v := sig[0] - 27
	copy(sig, sig[1:])
	sig[RecoveryIDOffset] = v
	return sig, nil
}

// VerifySignature checks that the given public key created signature over hash.
// verifsignature检查给定的公钥是否通过哈希创建了签名。
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// 公钥格式为压缩(33字节)或未压缩(65字节)。
// The signature should have the 64 byte [R || S] format.
// 签名应该有 64 字节 [R || S] 格式。
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	var r, s btcec.ModNScalar
	if r.SetByteSlice(signature[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	sig := btc_ecdsa.NewSignature(&r, &s)
	key, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if s.IsOverHalfOrder() {
		return false
	}
	return sig.Verify(hash, key)
}

// DecompressPubkey parses a public key in the 33-byte compressed format.
// DecompressPubkey 解析 33 字节压缩格式的公钥。
func DecompressPubkey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, errors.New("invalid compressed public key length")
	}
	key, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return nil, err
	}
	return key.ToECDSA(), nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format. The
// provided PublicKey must be valid. Namely, the coordinates must not be larger
// than 32 bytes each, they must be less than the field prime, and it must be a
// point on the secp256k1 curve. This is the case for a PublicKey constructed by
// elliptic.Unmarshal (see UnmarshalPubkey), or by ToECDSA and ecdsa.GenerateKey
// when constructing a PrivateKey.
func CompressPubkey(pubkey *ecdsa.PublicKey) []byte {
	// NOTE: the coordinates may be validated with
	// btcec.ParsePubKey(FromECDSAPub(pubkey))
	var x, y btcec.FieldVal
	x.SetByteSlice(pubkey.X.Bytes())
	y.SetByteSlice(pubkey.Y.Bytes())
	return btcec.NewPublicKey(&x, &y).SerializeCompressed()
}

// S256 returns an instance of the secp256k1 curve.
func S256() elliptic.Curve {
	return btcec.S256()
}
