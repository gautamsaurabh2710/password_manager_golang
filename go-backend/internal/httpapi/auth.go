package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"password-manager-go/internal/mailer"
	"password-manager-go/internal/models"
	"password-manager-go/internal/security"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type registerRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type otpRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (api *API) register(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request registerRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	plainPassword, err := api.decryptClientPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be encrypted before sending"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var existing models.User
	err = api.db.Users.FindOne(ctx, bson.M{"email": request.Email}).Decode(&existing)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "User already exists"})
		return
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	otp := randomDigits()
	otpHash, err := hashText(otp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	user := models.User{
		Name:       request.Name,
		Email:      request.Email,
		Password:   string(hash),
		OTP:        otpHash,
		OTPExpires: time.Now().Add(10 * time.Minute),
	}

	if _, err := api.db.Users.InsertOne(ctx, user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	if err := mailer.SendOTP(request.Email, otp, api.cfg.EmailUser, api.cfg.EmailPass); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"hint":    "Check EMAIL_USER/EMAIL_PASS and server email provider configuration",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "OTP sent to email, please verify"})
}

func (api *API) verifyOTP(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request otpRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	err := api.db.Users.FindOne(ctx, bson.M{"email": request.Email}).Decode(&user)
	if err != nil || time.Now().After(user.OTPExpires) || !checkText(user.OTP, request.OTP) {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid OTP"})
		return
	}

	token, err := security.GenerateToken(user.ID.Hex(), api.cfg.JWTSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	_, _ = api.db.Users.UpdateByID(ctx, user.ID, bson.M{"$unset": bson.M{"otp": "", "otpExpires": ""}})
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func (api *API) login(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request loginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	plainPassword, err := api.decryptClientPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be encrypted before sending"})
		return
	}
	if api.cfg.EmailUser == "" || api.cfg.EmailPass == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server email is not configured", "hint": "Missing EMAIL_USER/EMAIL_PASS in .env"})
		return
	}
	if api.cfg.MongoURI == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Database is not configured", "hint": "Missing MONGO_URI in .env"})
		return
	}
	if api.cfg.JWTSecret == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Auth is not configured", "hint": "Missing JWT_SECRET in .env"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	if err := api.db.Users.FindOne(ctx, bson.M{"email": request.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plainPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid credentials"})
		return
	}

	otp := randomDigits()
	otpHash, err := hashText(otp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	_, err = api.db.Users.UpdateByID(ctx, user.ID, bson.M{"$set": bson.M{
		"otp":        otpHash,
		"otpExpires": time.Now().Add(10 * time.Minute),
	}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	if err := mailer.SendOTP(request.Email, otp, api.cfg.EmailUser, api.cfg.EmailPass); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
			"hint":    "Check EMAIL_USER/EMAIL_PASS and Mongo/JWT env vars",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to email, please verify"})
}

func (api *API) logout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (api *API) forgotPassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request forgotPasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	var user models.User
	if err := api.db.Users.FindOne(ctx, bson.M{"email": request.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "User not found"})
		return
	}

	resetToken, err := secureToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	_, err = api.db.Users.UpdateByID(ctx, user.ID, bson.M{"$set": bson.M{
		"resetToken":        resetToken,
		"resetTokenExpires": time.Now().Add(10 * time.Minute),
	}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"resetToken": resetToken})
}

func (api *API) resetPassword(c *gin.Context) {
	if !requireDB(c, api.db) {
		return
	}

	var request resetPasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request body"})
		return
	}
	plainPassword, err := api.decryptClientPassword(request.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be encrypted before sending"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}

	result, err := api.db.Users.UpdateOne(ctx, bson.M{
		"resetToken":        request.Token,
		"resetTokenExpires": bson.M{"$gt": time.Now()},
	}, bson.M{
		"$set":   bson.M{"password": string(hash)},
		"$unset": bson.M{"resetToken": "", "resetTokenExpires": ""},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Server error"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid or expired token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

func secureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashText(value string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	return string(hash), err
}

func checkText(hash, value string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(value)) == nil
}

func (api *API) decryptClientPassword(value string) (string, error) {
	return security.DecryptTransportValue(api.transportPrivateKey, value)
}
