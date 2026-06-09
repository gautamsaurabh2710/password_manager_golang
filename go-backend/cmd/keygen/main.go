package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	jwtSecret := randomSecret(48)
	encryptionKey := randomSecret(32)

	fmt.Println("JWT_SECRET=" + jwtSecret)
	fmt.Println("ENCRYPTION_KEY=" + encryptionKey)
}

func randomSecret(size int) string {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes)
}
