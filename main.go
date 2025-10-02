package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/gorm"
	"com.trader/database"
	"com.trader/api"
	"com.trader/models"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using default values")
	}

	// Initialize database
	db := database.Init()
	
	// Auto-migrate database models in correct order
	if err := db.AutoMigrate(
		&models.User{},
		&models.Account{},
		&models.TradingPair{},
		&models.Transaction{},
		&models.ProfitStatistics{},
		&models.PlatformActivity{},
		&models.Settings{},
		&models.KYCSubmission{},
		&models.AuthChallenge{},
	); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create default trading pairs if they don't exist
	createDefaultTradingPairs(db)

	// Setup API routes
	router := api.NewAPIRouter()
	server := router.SetupRoutes()

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting Trader API server on port %s", port)
	log.Fatal(server.Run(":" + port))
}

func createDefaultTradingPairs(db *gorm.DB) {
	defaultPairs := []models.TradingPair{
		{Symbol: "BTC/USD", BaseAsset: "BTC", QuoteAsset: "USD", MinQty: 0.001, MaxQty: 1000, StepSize: 0.001, MinPrice: 0.01, MaxPrice: 1000000, TickSize: 0.01, IsActive: true},
		{Symbol: "ETH/USD", BaseAsset: "ETH", QuoteAsset: "USD", MinQty: 0.01, MaxQty: 10000, StepSize: 0.01, MinPrice: 0.01, MaxPrice: 100000, TickSize: 0.01, IsActive: true},
		{Symbol: "LTC/USD", BaseAsset: "LTC", QuoteAsset: "USD", MinQty: 0.1, MaxQty: 100000, StepSize: 0.1, MinPrice: 0.01, MaxPrice: 10000, TickSize: 0.01, IsActive: true},
		{Symbol: "ADA/USD", BaseAsset: "ADA", QuoteAsset: "USD", MinQty: 10, MaxQty: 1000000, StepSize: 10, MinPrice: 0.0001, MaxPrice: 100, TickSize: 0.0001, IsActive: true},
	}

	for _, pair := range defaultPairs {
		var existingPair models.TradingPair
		if err := db.Where("symbol = ?", pair.Symbol).First(&existingPair).Error; err != nil {
			db.Create(&pair)
		}
	}
}
