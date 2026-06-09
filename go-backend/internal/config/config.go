package config

import (
	"net/url"
	"os"
	"strings"
)

type Config struct {
	Port          string
	MongoURI      string
	MongoDB       string
	JWTSecret     string
	EncryptionKey string
	EmailUser     string
	EmailPass     string
}

func Load() Config {
	mongoURI := strings.TrimSpace(os.Getenv("MONGO_URI"))
	return Config{
		Port:          env("PORT", "5000"),
		MongoURI:      mongoURI,
		MongoDB:       mongoDatabaseName(mongoURI),
		JWTSecret:     strings.TrimSpace(os.Getenv("JWT_SECRET")),
		EncryptionKey: strings.TrimSpace(os.Getenv("ENCRYPTION_KEY")),
		EmailUser:     strings.TrimSpace(os.Getenv("EMAIL_USER")),
		EmailPass:     strings.TrimSpace(os.Getenv("EMAIL_PASS")),
	}
}

func mongoDatabaseName(uri string) string {
	if configured := strings.TrimSpace(os.Getenv("MONGO_DB")); configured != "" {
		return configured
	}

	parsed, err := url.Parse(uri)
	if err == nil {
		name := strings.Trim(strings.TrimSpace(parsed.Path), "/")
		if name != "" {
			return name
		}
	}

	return "test"
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
