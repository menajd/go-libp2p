// Package crypto implements various cryptographic utilities used by libp2p.
// This includes a Public and Private key interface and key implementations
// for supported key algorithms.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"

	"github.com/libp2p/go-libp2p/core/crypto/pb"

	"google.golang.org/protobuf/proto"
)

const (
	// RSA is an enum for the supported RSA key type
	RSA = iota
	// Ed25519 is an enum for the supported Ed25519 key type
	Ed25519
	// Secp256k1 is an enum for the supported Secp256k1 key type
	Secp256k1
	// ECDSA is an enum for the supported ECDSA key type
	ECDSA
	// ECDSA is an enum for the supported ECDSA key type
	BLS
)

var (
	// ErrBadKeyType is returned when a key is not supported
	ErrBadKeyType = errors.New("invalid or unsupported key type")
	// KeyTypes is a list of supported keys
	KeyTypes = []int{
		RSA,
		Ed25519,
		Secp256k1,
		ECDSA,
		BLS,
	}
)

// PubKeyUnmarshaller is a func that creates a PubKey from a given slice of bytes
type PubKeyUnmarshaller func(data []byte) (PubKey, error)

// PrivKeyUnmarshaller is a func that creates a PrivKey from a given slice of bytes
type PrivKeyUnmarshaller func(data []byte) (PrivKey, error)

// PubKeyUnmarshallers is a map of unmarshallers by key type
var PubKeyUnmarshallers = map[pb.KeyType]PubKeyUnmarshaller{
	pb.KeyType_RSA:       UnmarshalRsaPublicKey,
	pb.KeyType_Ed25519:   UnmarshalEd25519PublicKey,
	pb.KeyType_Secp256k1: UnmarshalSecp256k1PublicKey,
	pb.KeyType_ECDSA:     UnmarshalECDSAPublicKey,
	pb.KeyType_BLS:       UnmarshalBLSPublicKey,
}

// PrivKeyUnmarshallers is a map of unmarshallers by key type
var PrivKeyUnmarshallers = map[pb.KeyType]PrivKeyUnmarshaller{
	pb.KeyType_RSA:       UnmarshalRsaPrivateKey,
	pb.KeyType_Ed25519:   UnmarshalEd25519PrivateKey,
	pb.KeyType_Secp256k1: UnmarshalSecp256k1PrivateKey,
	pb.KeyType_ECDSA:     UnmarshalECDSAPrivateKey,
	pb.KeyType_BLS:       UnmarshalBLSPrivateKey,
}

// Key represents a crypto key that can be compared to another key
type Key interface {
	// Equals checks whether two PubKeys are the same
	Equals(Key) bool

	// Raw returns the raw bytes of the key (not wrapped in the
	// libp2p-crypto protobuf).
	//
	// This function is the inverse of {Priv,Pub}KeyUnmarshaler.
	Raw() ([]byte, error)

	// Type returns the protobuf key type.
	Type() pb.KeyType
}

// PrivKey represents a private key that can be used to generate a public key and sign data
type PrivKey interface {
	Key

	// Cryptographically sign the given bytes
	Sign([]byte) ([]byte, error)

	// Return a public key paired with this private key
	GetPublic() PubKey
}

// PubKey is a public key that can be used to verify data signed with the corresponding private key
type PubKey interface {
	Key

	// Verify that 'sig' is the signed hash of 'data'
	Verify(data []byte, sig []byte) (bool, error)
}

// GenSharedKey generates the shared key from a given private key
type GenSharedKey func([]byte) ([]byte, error)

// GenerateKeyPair generates a private and public key
func GenerateKeyPair(typ, bits int) (PrivKey, PubKey, error) {
	return GenerateKeyPairWithReader(typ, bits, rand.Reader)
}

// GenerateKeyPairWithReader returns a keypair of the given type and bit-size
func GenerateKeyPairWithReader(typ, bits int, src io.Reader) (PrivKey, PubKey, error) {
	switch typ {
	case RSA:
		return GenerateRSAKeyPair(bits, src)
	case Ed25519:
		return GenerateEd25519Key(src)
	case Secp256k1:
		return GenerateSecp256k1Key(src)
	case ECDSA:
		return GenerateECDSAKeyPair(src)
	case BLS:
		return GenerateBLSKeyPair(src)
	default:
		return nil, nil, ErrBadKeyType
	}
}

// UnmarshalPublicKey converts a protobuf serialized public key into its
// representative object
func UnmarshalPublicKey(data []byte) (PubKey, error) {
	pmes := new(pb.PublicKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromProto(pmes)
}

// PublicKeyFromProto converts an unserialized protobuf PublicKey message
// into its representative object.
func PublicKeyFromProto(pmes *pb.PublicKey) (PubKey, error) {
	um, ok := PubKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	data := pmes.GetData()

	pk, err := um(data)
	if err != nil {
		return nil, err
	}

	switch tpk := pk.(type) {
	case *RsaPublicKey:
		tpk.cached, _ = proto.Marshal(pmes)
	}

	return pk, nil
}

// MarshalPublicKey converts a public key object into a protobuf serialized
// public key
func MarshalPublicKey(k PubKey) ([]byte, error) {
	pbmes, err := PublicKeyToProto(k)
	if err != nil {
		return nil, err
	}

	return proto.Marshal(pbmes)
}

// PublicKeyToProto converts a public key object into an unserialized
// protobuf PublicKey message.
func PublicKeyToProto(k PubKey) (*pb.PublicKey, error) {
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	return &pb.PublicKey{
		Type: k.Type().Enum(),
		Data: data,
	}, nil
}

// UnmarshalPrivateKey converts a protobuf serialized private key into its
// representative object
func UnmarshalPrivateKey(data []byte) (PrivKey, error) {
	pmes := new(pb.PrivateKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}

	um, ok := PrivKeyUnmarshallers[pmes.GetType()]
	if !ok {
		return nil, ErrBadKeyType
	}

	return um(pmes.GetData())
}

// MarshalPrivateKey converts a key object into its protobuf serialized form.
func MarshalPrivateKey(k PrivKey) ([]byte, error) {
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(&pb.PrivateKey{
		Type: k.Type().Enum(),
		Data: data,
	})
}

// ConfigDecodeKey decodes from b64 (for config file) to a byte array that can be unmarshalled.
func ConfigDecodeKey(b string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b)
}

// ConfigEncodeKey encodes a marshalled key to b64 (for config file).
func ConfigEncodeKey(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// KeyEqual checks whether two Keys are equivalent (have identical byte representations).
func KeyEqual(k1, k2 Key) bool {
	if k1 == k2 {
		return true
	}

	return k1.Equals(k2)
}

func basicEquals(k1, k2 Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
