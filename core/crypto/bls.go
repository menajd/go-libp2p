package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"github.com/cloudflare/circl/sign/bls"
	pb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/internal/catch"
)

type BLSPrivateKey struct {
	s *bls.PrivateKey[bls.KeyG1SigG2]
}

type BLSPublicKey struct {
	p *bls.PublicKey[bls.KeyG1SigG2]
}

func GenerateBLSKeyPair(src io.Reader) (PrivKey, PubKey, error) {
	ikm := make([]byte, 32)
	rand.Read(ikm)
	salt := sha256.Sum256([]byte("BLS-SIG-KEYGEN-SALT-"))
	prvKey, err := bls.KeyGen[bls.KeyG1SigG2](ikm, salt[:], nil)
	if err != nil {
		return nil, nil, err
	}
	return &BLSPrivateKey{s: prvKey}, &BLSPublicKey{p: prvKey.PublicKey()}, nil
}

// Type of the private key (BLS).
func (k *BLSPrivateKey) Type() pb.KeyType {
	return pb.KeyType_BLS
}

func (k *BLSPrivateKey) Raw() ([]byte, error) {
	return k.s.MarshalBinary()
}

// Equals compares two BLS private keys.
func (k *BLSPrivateKey) Equals(o Key) bool {
	edk, ok := o.(*BLSPrivateKey)
	if !ok {
		return basicEquals(k, o)
	}
	kBytes, _ := k.s.MarshalBinary()
	edkBytes, _ := edk.s.MarshalBinary()
	return subtle.ConstantTimeCompare(kBytes, edkBytes) == 1
}

// GetPublic returns an BLS public key from a private key.
func (k *BLSPrivateKey) GetPublic() PubKey {
	return &BLSPublicKey{p: k.s.PublicKey()}
}

// Sign returns a signature from an input message.
func (k *BLSPrivateKey) Sign(msg []byte) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "BLS signing") }()

	return bls.Sign(k.s, msg), nil
}

// Type of the public key (BLS).
func (k *BLSPublicKey) Type() pb.KeyType {
	return pb.KeyType_BLS
}

// Raw public key bytes.
func (k *BLSPublicKey) Raw() ([]byte, error) {
	return k.p.MarshalBinary()
}

// Equals compares two BLS public keys.
func (k *BLSPublicKey) Equals(o Key) bool {
	edk, ok := o.(*BLSPublicKey)
	if !ok {
		return basicEquals(k, o)
	}
	bt, _ := k.Raw()
	bedk, _ := edk.Raw()
	return bytes.Equal(bt, bedk)
}

// Verify checks a signature against the input data.
func (k *BLSPublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	return bls.Verify(k.p, data, sig), nil
}

// UnmarshalBLSPublicKey returns a public key from input bytes.
func UnmarshalBLSPublicKey(data []byte) (PubKey, error) {
	prv := &BLSPublicKey{}

	err := prv.p.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return prv, nil
}

// UnmarshalBLSPrivateKey returns a private key from input bytes.
func UnmarshalBLSPrivateKey(data []byte) (PrivKey, error) {
	prv := &BLSPrivateKey{}

	err := prv.s.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	return prv, nil
}
