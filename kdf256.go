package srp

import (
	"crypto/sha256"
	"math/big"
)

func KDF256(salt []byte, UUID string, OS string, clientID string, clientSecret string) (x *big.Int) {
	uuid := []byte(PreparePassword(UUID))
	os := []byte(PreparePassword(OS))
	c_id := []byte(PreparePassword(clientID))
	c_sec := []byte(PreparePassword(clientSecret))

	innerHasher := sha256.New()
	if _, err := innerHasher.Write(uuid); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write([]byte(":")); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write(os); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write([]byte(":")); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write(c_id); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write([]byte(":")); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write(c_sec); err != nil {
		panic(err)
	}

	ih := innerHasher.Sum(nil)

	oHasher := sha256.New()
	if _, err := oHasher.Write(salt); err != nil {
		panic(err)
	}
	if _, err := oHasher.Write(ih); err != nil {
		panic(err)
	}

	h := oHasher.Sum(nil)
	x = bigIntFromBytes(h)
	return x
}

// PreparePassword strips leading and trailing white space
// and normalizes to unicode NFKD.
