package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"password-manager-go/internal/models"
	"password-manager-go/internal/security"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type passwordRequest struct {
	Website  string `json:"website"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type revealPasswordRequest struct {
	PublicKey string `json:"publicKey"`
}

func (api *API) addPassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request passwordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	request.Website = strings.TrimSpace(request.Website)
	request.Username = strings.TrimSpace(request.Username)
	request.Password = strings.TrimSpace(request.Password)
	if request.Website == "" || request.Username == "" || request.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Website, username, and password are required"})
		return
	}
	plainPassword, err := api.decryptClientPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be encrypted before sending"})
		return
	}

	userObjectID, err := primitive.ObjectIDFromHex(userIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"userId":   userObjectID,
		"website":  request.Website,
		"username": request.Username,
	}

	var existingPassword models.Password
	err = api.db.Passwords.FindOne(ctx, filter).Decode(&existingPassword)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"message": "Password already exists for this website and username"})
		return
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add password"})
		return
	}

	encryptedPassword, err := security.Encrypt(plainPassword, api.cfg.EncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add password"})
		return
	}

	password := models.Password{
		UserID:            userObjectID,
		Website:           request.Website,
		Username:          request.Username,
		EncryptedPassword: encryptedPassword,
	}

	result, err := api.db.Passwords.InsertOne(ctx, password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add password"})
		return
	}
	if objectID, ok := result.InsertedID.(primitive.ObjectID); ok {
		password.ID = objectID
	}

	c.JSON(http.StatusCreated, password)
}

func (api *API) getPasswords(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	userObjectID, err := primitive.ObjectIDFromHex(userIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	cursor, err := api.db.Passwords.Find(ctx, bson.M{"userId": userObjectID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve passwords"})
		return
	}
	defer cursor.Close(ctx)

	var passwords []models.Password
	if err := cursor.All(ctx, &passwords); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve passwords"})
		return
	}

	c.JSON(http.StatusOK, passwords)
}

func (api *API) revealPassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request revealPasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil || strings.TrimSpace(request.PublicKey) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Browser public key is required"})
		return
	}

	userObjectID, err := primitive.ObjectIDFromHex(userIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	passwordID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid password id"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var password models.Password
	err = api.db.Passwords.FindOne(ctx, bson.M{
		"_id":    passwordID,
		"userId": userObjectID,
	}).Decode(&password)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Password not found"})
		return
	}

	plainPassword, err := security.Decrypt(password.EncryptedPassword, api.cfg.EncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to reveal password"})
		return
	}

	encryptedForBrowser, err := security.EncryptForBrowser(request.PublicKey, plainPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid browser public key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"password": encryptedForBrowser})
}

func (api *API) updatePassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request passwordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	request.Website = strings.TrimSpace(request.Website)
	request.Username = strings.TrimSpace(request.Username)
	request.Password = strings.TrimSpace(request.Password)
	if request.Website == "" || request.Username == "" || request.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Website, username, and password are required"})
		return
	}

	plainPassword, err := api.decryptClientPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be encrypted before sending"})
		return
	}

	userObjectID, err := primitive.ObjectIDFromHex(userIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	passwordID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid password id"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	duplicateFilter := bson.M{
		"_id":      bson.M{"$ne": passwordID},
		"userId":   userObjectID,
		"website":  request.Website,
		"username": request.Username,
	}

	var duplicatePassword models.Password
	err = api.db.Passwords.FindOne(ctx, duplicateFilter).Decode(&duplicatePassword)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"message": "Password already exists for this website and username"})
		return
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	encryptedPassword, err := security.Encrypt(plainPassword, api.cfg.EncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	result, err := api.db.Passwords.UpdateOne(ctx, bson.M{
		"_id":    passwordID,
		"userId": userObjectID,
	}, bson.M{
		"$set": bson.M{
			"website":           request.Website,
			"username":          request.Username,
			"encryptedPassword": encryptedPassword,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Password not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func (api *API) deletePassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	userObjectID, err := primitive.ObjectIDFromHex(userIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	passwordID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid password id"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	result, err := api.db.Passwords.DeleteOne(ctx, bson.M{
		"_id":    passwordID,
		"userId": userObjectID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete password"})
		return
	}
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Password not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password deleted successfully"})
}
