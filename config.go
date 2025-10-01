package main

import (
	"os"
	"strconv"
)

type Config struct {
	Database DatabaseConfig
	JWT      JWTConfig
	Server   ServerConfig
	CORS     CORSConfig
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Name     string
}

type JWTConfig struct {
	Secret string
}

type ServerConfig struct {
	Port    string
	GinMode string
}

type CORSConfig struct {
	Origins []string
}

func LoadConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 3306),
			User:     getEnv("DB_USER", "colls"),
			Password: getEnv("DB_PASSWORD", "1234"),
			Name:     getEnv("DB_NAME", "task"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
		},
		Server: ServerConfig{
			Port:    getEnv("PORT", "8080"),
			GinMode: getEnv("GIN_MODE", "debug"),
		},
		CORS: CORSConfig{
			Origins: []string{
				"http://localhost:3000",
				"http://localhost:3001",
				"http://127.0.0.1:3000",
				"http://127.0.0.1:3001",
			},
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
