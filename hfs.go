// hfs.go - Hybrid Forward Secrecy extension.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package noise

import (
	"io"

	"git.schwanenlied.me/yawning/kyber"
)

type HFSKey interface {
	Public() []byte
}

// HFSFunc implements a hybrid forward secrecy function, for the Noise HFS
// extension (version 1draft-5).
//
// See: https://github.com/noiseprotocol/noise_spec/blob/master/extensions/ext_hybrid_forward_secrecy.md
type HFSFunc interface {
	// GenerateKeypairF generates a new key pair for the hybrid forward
	// secrecy algorithm relative to a remote public key rf. The rf value
	// will be empty for the first "f" token in the handshake, and non-empty
	// for the second "f" token.
	GenerateKeypairF(rng io.Reader, rf []byte) HFSKey

	// FF performs a hybrid forward secrecy calculation that mixes a local key
	// pair with a remote public key.
	FF(keypair HFSKey, pubkey []byte) []byte

	// FLen1 is a constant specifying the size in bytes of the output from
	// GenerateKeypairF(rf) when rf is empty.
	FLen1() int

	// Flen2 is a constant specifying the size in bytes of the output from
	// GenerateKeypairF(rf) when rf is not empty.
	FLen2() int

	// FLen is constant specifying the size in bytes of the output from FF().
	FLen() int

	// HFSName is the name of the HFS function.
	HFSName() string
}

// HFSKyber is the Kyber crypto_kem_keypair HFS function.
var HFSKyber HFSFunc = hfsKyber{}

type hfsKyber struct{}

type keyKyberInitiator struct {
	privKey *kyber.PrivateKey
	pubKey  *kyber.PublicKey
}

func (k *keyKyberInitiator) Public() []byte {
	return k.pubKey.Bytes()
}

type keyKyberResponder struct {
	pubKey *kyber.PublicKey
	shared []byte
}

func (k *keyKyberResponder) Public() []byte {
	return k.pubKey.Bytes()
}

func (h hfsKyber) GenerateKeypairF(rng io.Reader, rf []byte) HFSKey {
	if rf != nil {
		if len(rf) != h.FLen1() {
			panic("noise/hfs: rf is not Kyber1024.PublicKeySize")
		}
		initiatorPk, err := kyber.Kyber1024.PublicKeyFromBytes(rf)
		if err != nil {
			panic("noise/hfs: rf deserialization error: " + err.Error())
		}

		cipherText, shared, err := initiatorPk.KEMEncrypt(rng)
		if err != nil {
			panic("noise/hfs: Kyber KEMEncrypt error: " + err.Error())
		}

		pubKey, err := kyber.Kyber1024.PublicKeyFromBytes(cipherText)
		if err != nil {
			panic("noise/hfs: rf deserialization error: " + err.Error())
		}

		return &keyKyberResponder{
			pubKey: pubKey,
			shared: shared,
		}
	}

	// Generate the keypair as Initiator.
	pubKey, privKey, err := kyber.Kyber1024.GenerateKeyPair(rng)
	if err != nil {
		panic("noise/hfs: kyber.Kyber1024.GenerateKeyPair(): " + err.Error())
	}

	return &keyKyberInitiator{
		privKey: privKey,
		pubKey:  pubKey,
	}
}

func (h hfsKyber) FF(keypair HFSKey, pubkey []byte) []byte {
	switch k := keypair.(type) {
	case *keyKyberInitiator:
		if len(pubkey) != h.FLen1() {
			panic("noise/hfs: pubkey is not Kyber1024.PublicKeySize")
		}
		return k.privKey.KEMDecrypt(pubkey)
	case *keyKyberResponder:
		return k.shared
	default:
	}
	panic("noise/fs: FF(): unsupported keypair type")
}

func (hfsKyber) FLen1() int {
	return kyber.Kyber1024.PublicKeySize()
}

func (hfsKyber) FLen2() int {
	return kyber.Kyber1024.CipherTextSize()
}

func (hfsKyber) FLen() int {
	return kyber.SymSize
}

func (hfsKyber) HFSName() string {
	return "Kyber"
}

var hfsNull HFSFunc = hfsNullImpl{}

type hfsNullImpl struct{}

func (hfsNullImpl) GenerateKeypairF(r io.Reader, rf []byte) HFSKey {
	panic("noise/hfs: GenerateKeypairF called for null HFS")
}

func (hfsNullImpl) FF(keypair HFSKey, pubkey []byte) []byte {
	panic("noise/hfs: FF called for null HFS")
}

func (hfsNullImpl) FLen1() int {
	return 0
}

func (hfsNullImpl) FLen2() int {
	return 0
}

func (hfsNullImpl) FLen() int {
	return 0
}

func (hfsNullImpl) HFSName() string {
	return "(null)"
}
