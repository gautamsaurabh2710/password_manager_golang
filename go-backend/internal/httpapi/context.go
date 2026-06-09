package httpapi

import "github.com/gin-gonic/gin"

func userIDFromContext(c *gin.Context) string {
	value, exists := c.Get("userID")
	if !exists {
		return ""
	}

	userID, _ := value.(string)
	return userID
}
