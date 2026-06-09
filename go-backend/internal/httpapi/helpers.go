package httpapi

import (
	"crypto/rand"
	"math/big"
	"net/http"

	"password-manager-go/internal/database"

	"github.com/gin-gonic/gin"
)

func requireDB(c *gin.Context, db *database.DB) bool {
	if db != nil {
		return true
	}

	c.JSON(http.StatusServiceUnavailable, gin.H{
		"message": "Database is not connected",
		"hint":    "Check MONGO_URI, MongoDB Atlas network access, and TLS connectivity",
	})
	return false
}

func randomDigits() string {
	const digits = "0123456789"
	code := make([]byte, 6)
	for index := range code {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			code[index] = '0'
			continue
		}
		code[index] = digits[value.Int64()]
	}
	if code[0] == '0' {
		code[0] = '1'
	}
	return string(code)
}
