package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

func RandomString(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(buf)
}
