package nosurf

import (
	"crypto/sha256"
)

// Masks/unmasks the given data *in place*
// with the given key
// Slices must be of the same length, or oneTimePad will panic
func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

func maskToken(id string, data []byte) []byte {
	if len(data) != tokenLength || len(id) == 0 {
		return nil
	}

	// tokenLength*2 == len(enckey + token)
	result := make([]byte, tokenLength)
	shaToken := sha256.Sum256([]byte(id))
	//shift 1 bit
	for i := 0; i < len(shaToken);i++  {
		shaToken[i] = shaToken[i] << 1
	}
	copy(result, shaToken[:])

	oneTimePad(result, data)
	return result
}

func unmaskToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	key := data[:tokenLength]
	token := data[tokenLength:]
	oneTimePad(token, key)

	return token
}
