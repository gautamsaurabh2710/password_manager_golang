package httpapi

import (
	"crypto/rsa"
	"log"
	"net/http"
	"strings"

	"password-manager-go/internal/config"
	"password-manager-go/internal/database"
	"password-manager-go/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

type API struct {
	cfg                 *config.Config
	db                  *database.DB
	transportPrivateKey *rsa.PrivateKey
	transportPublicKey  string
}

func NewRouter(cfg config.Config, db *database.DB) http.Handler {
	transportPrivateKey, err := security.GenerateTransportKey()
	if err != nil {
		log.Fatalf("Failed to create transport key: %v", err)
	}
	transportPublicKey, err := security.PublicKeyPEM(transportPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create transport public key: %v", err)
	}

	api := &API{
		cfg:                 &cfg,
		db:                  db,
		transportPrivateKey: transportPrivateKey,
		transportPublicKey:  transportPublicKey,
	}
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(securityHeaders())

	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "API Working")
	})
	router.GET("/api/security/public-key", api.publicKey)

	authRoutes := router.Group("/api/auth")
	authRoutes.POST("/register", api.rateLimit(), api.register)
	authRoutes.POST("/verify-otp", api.rateLimit(), api.verifyOTP)
	authRoutes.POST("/login", api.rateLimit(), api.login)
	authRoutes.POST("/logout", api.logout)
	authRoutes.POST("/forgot-password", api.rateLimit(), api.forgotPassword)
	authRoutes.POST("/reset-password", api.rateLimit(), api.resetPassword)

	passwordRoutes := router.Group("/api/passwords")
	passwordRoutes.Use(api.auth())
	passwordRoutes.POST("", api.addPassword)
	passwordRoutes.GET("", api.getPasswords)
	passwordRoutes.POST("/:id/reveal", api.revealPassword)
	passwordRoutes.PUT("/:id", api.updatePassword)
	passwordRoutes.DELETE("/:id", api.deletePassword)

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "Route not found", "path": c.Request.URL.Path})
	})

	return cors.AllowAll().Handler(router)
}

func (api *API) publicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"publicKey": api.transportPublicKey})
}

func (api *API) rateLimit() gin.HandlerFunc {
	rate, _ := limiter.NewRateFromFormatted("5-M")
	instance := limiter.New(memory.NewStore(), rate)

	return func(c *gin.Context) {
		limitContext, err := instance.Get(c.Request.Context(), c.ClientIP())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Rate limiter error"})
			c.Abort()
			return
		}
		if limitContext.Reached {
			c.JSON(http.StatusTooManyRequests, gin.H{"message": "Too many requests from this IP, please try again after 15 minutes"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (api *API) auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "No token"})
			c.Abort()
			return
		}

		tokenValue := authHeader
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenValue = strings.TrimPrefix(authHeader, "Bearer ")
		}

		claims, err := security.ParseToken(tokenValue, api.cfg.JWTSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Next()
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}
