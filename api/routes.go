package api

import (
	"github.com/gin-gonic/gin"
	"com.trader/database"
	"com.trader/users"
	"com.trader/models"
)

type APIRouter struct {
	userHandlers *users.UserHandlers
}

func NewAPIRouter() *APIRouter {
	return &APIRouter{
		userHandlers: users.NewUserHandlers(),
	}
}

// SetupRoutes configures all API routes
func (r *APIRouter) SetupRoutes() *gin.Engine {
	router := gin.New()
	
	// Add middleware
	router.Use(CORSMiddleware())
	router.Use(ErrorHandler())
	router.Use(LoggerMiddleware())
	router.Use(RateLimitMiddleware())

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "Trader API is running",
		})
	})

	// API version 1
	v1 := router.Group("/api/v1")
	{
		// Public routes (no authentication required)
		public := v1.Group("/")
		{
            // Legacy auth (kept for now)
            public.POST("/auth/register", r.userHandlers.Register)
            public.POST("/auth/login", r.userHandlers.Login)

            // Wallet auth
            public.POST("/auth/wallet/challenge", r.userHandlers.RequestWalletChallenge)
            public.POST("/auth/wallet/verify", r.userHandlers.VerifyWalletSignature)
            public.POST("/auth/token/refresh", r.userHandlers.RefreshToken)
		}

		// Protected routes (authentication required)
		protected := v1.Group("/")
		protected.Use(r.userHandlers.AuthMiddleware())
		{
            // Session
            protected.POST("/auth/logout", r.userHandlers.Logout)

			// User routes
			user := protected.Group("/user")
			{
				user.GET("/profile", r.userHandlers.GetProfile)
				user.PUT("/profile", r.userHandlers.UpdateProfile)
                // Platform activities under user per spec
                user.GET("/platform-activities", r.GetPlatformActivities)
			}

			// Trading routes
            trading := protected.Group("/trading")
			{
				trading.GET("/accounts", r.GetAccounts)
                trading.GET("/orders", r.GetTransactions)
                trading.POST("/orders", r.CreateTransaction)
				trading.GET("/profit-statistics", r.GetProfitStatistics)
			}

            // Market data
            market := protected.Group("/market")
            {
                market.GET("/trading-pairs", r.GetTradingPairs)
                // price-data/{pair_id} and overview to be implemented
            }

			// Settings routes
			settings := protected.Group("/settings")
			{
				settings.GET("/", r.GetSettings)
				settings.PUT("/", r.UpdateSettings)
			}

			// Leverage routes
			leverage := protected.Group("/leverage")
			{
                leverage.GET("/", r.GetLeverage)
                leverage.PUT("/", r.UpdateLeverage)
			}
		}
	}

	return router
}

// Trading handlers (these would be in a separate trading package in a larger app)
func (r *APIRouter) GetAccounts(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var accounts []models.Account
	if err := db.Where("user_id = ?", user.ID).Find(&accounts).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch accounts"})
		return
	}

	c.JSON(200, gin.H{"accounts": accounts})
}

func (r *APIRouter) GetTransactions(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var transactions []models.Transaction
	if err := db.Where("user_id = ?", user.ID).Order("created_at DESC").Limit(50).Find(&transactions).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch transactions"})
		return
	}

	c.JSON(200, gin.H{"transactions": transactions})
}

func (r *APIRouter) CreateTransaction(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var req struct {
		Type     string  `json:"type" binding:"required"`
		Symbol   string  `json:"symbol" binding:"required"`
		Amount   float64 `json:"amount" binding:"required"`
		Price    float64 `json:"price" binding:"required"`
		Leverage int     `json:"leverage"`
	}

	if err := database.Bind(c, &req); err != nil {
		c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	transaction := models.Transaction{
		UserID:     user.ID,
		Type:       req.Type,
		Symbol:     req.Symbol,
		Amount:     req.Amount,
		Price:      req.Price,
		TotalValue: req.Amount * req.Price,
		Leverage:   req.Leverage,
		Status:     "pending",
	}

	if err := db.Create(&transaction).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create transaction"})
		return
	}

	c.JSON(201, gin.H{
		"message":     "Transaction created successfully",
		"transaction": transaction,
	})
}

func (r *APIRouter) GetProfitStatistics(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var stats []models.ProfitStatistics
	if err := db.Where("user_id = ?", user.ID).Order("date DESC").Find(&stats).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch profit statistics"})
		return
	}

	c.JSON(200, gin.H{"statistics": stats})
}

func (r *APIRouter) GetPlatformActivities(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var activities []models.PlatformActivity
	if err := db.Where("user_id = ?", user.ID).Order("created_at DESC").Limit(100).Find(&activities).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch platform activities"})
		return
	}

	c.JSON(200, gin.H{"activities": activities})
}

func (r *APIRouter) GetTradingPairs(c *gin.Context) {
	db := database.GetConnection()

	var pairs []models.TradingPair
	if err := db.Where("is_active = ?", true).Find(&pairs).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch trading pairs"})
		return
	}

	c.JSON(200, gin.H{"trading_pairs": pairs})
}

func (r *APIRouter) GetSettings(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var settings models.Settings
	if err := db.Where("user_id = ?", user.ID).First(&settings).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch settings"})
		return
	}

	c.JSON(200, gin.H{"settings": settings})
}

func (r *APIRouter) UpdateSettings(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var req models.Settings
	if err := database.Bind(c, &req); err != nil {
		c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	req.UserID = user.ID
	if err := db.Where("user_id = ?", user.ID).Save(&req).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to update settings"})
		return
	}

	c.JSON(200, gin.H{
		"message":  "Settings updated successfully",
		"settings": req,
	})
}

func (r *APIRouter) GetLeverage(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	
	c.JSON(200, gin.H{
		"current_leverage": user.Leverage,
		"max_leverage":     100, // This could come from user settings
	})
}

func (r *APIRouter) UpdateLeverage(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var req struct {
		Leverage int `json:"leverage" binding:"required,min=1,max=100"`
	}

	if err := database.Bind(c, &req); err != nil {
		c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	if err := db.Model(user).Update("leverage", req.Leverage).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to update leverage"})
		return
	}

	c.JSON(200, gin.H{
		"message":          "Leverage updated successfully",
		"current_leverage": req.Leverage,
	})
}
