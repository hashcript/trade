package api

import (
    "time"
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
				user.GET("/platform-activities", r.GetUserPlatformActivities)
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
				market.GET("/price-data/:pair_id", r.GetPriceData)
            }

			// Security
			protected.GET("/security", r.GetSecurity)
			protected.PUT("/security", r.UpdateSecurity)
			// Trailing slash aliases for security as well
			protected.GET("/security/", r.GetSecurity)
			protected.PUT("/security/", r.UpdateSecurity)

			// Wallet routes
			wallet := protected.Group("/wallet")
			{
				wallet.GET("/balances", r.GetWalletBalances)
				wallet.GET("/get-wallets", r.GetWalletAddresses)
				wallet.POST("/deposit", r.CreateWalletDeposit)
			}

			// KYC routes
			kyc := protected.Group("/kyc")
			{
				kyc.POST("/submit", r.SubmitKYC)
				kyc.PUT("/submit", r.SubmitKYC)
				kyc.GET("/status", r.GetKYCStatus)
				kyc.GET("/history", r.GetKYCHistory)
			}

			// Settings routes
            settings := protected.Group("/settings")
			{
                // Support both with and without trailing slash
                settings.GET("/", r.GetSettings)
                settings.PUT("/", r.UpdateSettings)
                settings.GET("", r.GetSettings)
                settings.PUT("", r.UpdateSettings)
			}

			// Leverage routes
            leverage := protected.Group("/leverage")
			{
                // Support both with and without trailing slash
                leverage.GET("/", r.GetLeverage)
                leverage.PUT("/", r.UpdateLeverage)
                leverage.GET("", r.GetLeverage)
                leverage.PUT("", r.UpdateLeverage)
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

// Spec-compliant user platform activities
func (r *APIRouter) GetUserPlatformActivities(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    db := database.GetConnection()

    var lastDeposit models.Transaction
    db.Where("user_id = ? AND type = ?", user.ID, "deposit").Order("created_at DESC").First(&lastDeposit)

    var lastWithdrawal models.Transaction
    db.Where("user_id = ? AND type = ?", user.ID, "withdrawal").Order("created_at DESC").First(&lastWithdrawal)

    // Build response per spec
    resp := gin.H{
        "user_id":       user.ID,
        "registered_on": user.CreatedAt.Format(time.RFC3339),
        "last_login":    user.UpdatedAt.Format(time.RFC3339),
    }
    if lastDeposit.ID != 0 {
        resp["last_deposit"] = gin.H{
            "amount":    formatAmount(lastDeposit.TotalValue),
            "currency":  "USDT",
            "timestamp": lastDeposit.CreatedAt.Format(time.RFC3339),
        }
    }
    if lastWithdrawal.ID != 0 {
        resp["last_withdrawal"] = gin.H{
            "amount":    formatAmount(lastWithdrawal.TotalValue),
            "currency":  "USDT",
            "timestamp": lastWithdrawal.CreatedAt.Format(time.RFC3339),
        }
    }

    c.JSON(200, resp)
}

func (r *APIRouter) GetTradingPairs(c *gin.Context) {
	db := database.GetConnection()

	var pairs []models.TradingPair
	if err := db.Where("is_active = ?", true).Find(&pairs).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch trading pairs"})
		return
	}

    // Shape response to match frontend spec
    response := make([]gin.H, 0, len(pairs))
    for _, p := range pairs {
        // simple symbol meta mapping; replace with real data source later
        name := p.BaseAsset
        logo := ""
        categoryID := 1
        category := "Digital Assets"
        valueUSD := 0.0
        pct := 0.0
        high := 0.0
        low := 0.0
        vol := 0.0
        switch p.BaseAsset {
        case "BTC":
            name = "Bitcoin"
            logo = "https://assets.trustwallet.com/blockchains/bitcoin/info/logo.png"
            valueUSD = 100000
            pct = 2.34
            high = 101500
            low = 98000
            vol = 125000000
        case "ETH":
            name = "Ethereum"
            logo = "https://assets.trustwallet.com/blockchains/ethereum/info/logo.png"
            valueUSD = 3500
            pct = -1.5
            high = 3600
            low = 3450
            vol = 85000000
        }
        response = append(response, gin.H{
            "id":               p.ID,
            "symbol":           p.Symbol,
            "base_asset":       p.BaseAsset,
            "quote_asset":      p.QuoteAsset,
            "name":             name,
            "value_usd":        valueUSD,
            "percentage_change": pct,
            "high_24h":         high,
            "low_24h":          low,
            "volume_24h":       vol,
            "category_id":      categoryID,
            "category":         category,
            "logo_url":         logo,
            // Keep timestamps for possible frontend display
            "created_at":        p.CreatedAt.Format(time.RFC3339),
            "updated_at":        p.UpdatedAt.Format(time.RFC3339),
        })
    }

    c.JSON(200, gin.H{"trading_pairs": response})
}

// Market price-data per spec (mocked from transactions/prices placeholder)
func (r *APIRouter) GetPriceData(c *gin.Context) {
    pairID := c.Param("pair_id")
    interval := c.Query("interval")
    if interval == "" {
        interval = "1h"
    }
    // start_time is required per spec
    start := c.Query("start_time")
    if start == "" {
        c.JSON(400, gin.H{"error": "start_time is required"})
        return
    }
    // For now, return a simple placeholder consistent with spec
    c.JSON(200, gin.H{
        "pair_id":    pairID,
        "symbol":     "BTC/USD",
        "interval":   interval,
        "price_data": [][]interface{}{{1727789022, 100000}, {1727789025, 100010}},
    })
}

// Wallet list/address endpoint (stub)
func (r *APIRouter) GetWalletAddresses(c *gin.Context) {
    wallets := []gin.H{
        {"wallet_id": 1, "pair_id": 4, "symbol": "BTC", "address": "bc1qxyz...", "network": "Bitcoin"},
        {"wallet_id": 2, "pair_id": 20, "symbol": "USDT", "address": "0xabc123...", "network": "Ethereum (ERC20)"},
    }
    c.JSON(200, gin.H{"wallets": wallets})
}

// Wallet deposit endpoint (stub)
func (r *APIRouter) CreateWalletDeposit(c *gin.Context) {
    var req struct {
        WalletID int     `json:"wallet_id" binding:"required"`
        Amount   float64 `json:"amount" binding:"required"`
    }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
        return
    }
    c.JSON(201, gin.H{
        "deposit_id": "dep_abc123",
        "wallet_id": req.WalletID,
        "amount":     req.Amount,
        "status":     "completed",
        "created_at": time.Now().UTC().Format(time.RFC3339),
    })
}

// KYC submit (stub)
func (r *APIRouter) SubmitKYC(c *gin.Context) {
    c.JSON(200, gin.H{
        "kyc_submission_id": "kyc_sub_abc123",
        "status":            "processing",
        "submitted_at":      time.Now().UTC().Format(time.RFC3339),
        "estimated_processing_time": "2-24 hours",
    })
}

// KYC status (stub)
func (r *APIRouter) GetKYCStatus(c *gin.Context) {
    c.JSON(200, gin.H{
        "kyc_submission_id": "kyc_sub_abc123",
        "status":            "pending",
        "submitted_at":      time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
        "processing_stage":  "document_verification",
        "estimated_completion": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
        "can_trade": false,
    })
}

// KYC history (stub)
func (r *APIRouter) GetKYCHistory(c *gin.Context) {
    subs := []gin.H{
        {"kyc_submission_id": "kyc_sub_old1", "status": "rejected", "submitted_at": time.Now().AddDate(0, -1, 0).UTC().Format(time.RFC3339), "processed_at": time.Now().AddDate(0, -1, 0).Add(4 * time.Hour).UTC().Format(time.RFC3339), "rejection_reason": "Document expired"},
        {"kyc_submission_id": "kyc_sub_abc123", "status": "pending", "submitted_at": time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)},
    }
    c.JSON(200, gin.H{"submissions": subs})
}

// Security endpoints per spec (backed by Settings fields as placeholder)
func (r *APIRouter) GetSecurity(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    db := database.GetConnection()
    var settings models.Settings
    if err := db.Where("user_id = ?", user.ID).First(&settings).Error; err != nil {
        c.JSON(500, gin.H{"error": "Failed to fetch security"})
        return
    }
    c.JSON(200, gin.H{
        "requirePin": settings.TwoFactorAuth,
        "privacyMode": false,
    })
}

func (r *APIRouter) UpdateSecurity(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    db := database.GetConnection()
    var req struct {
        RequirePin  bool `json:"requirePin"`
        PrivacyMode bool `json:"privacyMode"`
    }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
        return
    }
    if err := db.Model(&models.Settings{}).Where("user_id = ?", user.ID).Updates(map[string]interface{}{
        "two_factor_auth": req.RequirePin,
    }).Error; err != nil {
        c.JSON(500, gin.H{"error": "Failed to update security"})
        return
    }
    c.JSON(200, gin.H{
        "requirePin": req.RequirePin,
        "privacyMode": req.PrivacyMode,
    })
}

// Wallet balances per spec (placeholder)
func (r *APIRouter) GetWalletBalances(c *gin.Context) {
    includeZero := c.DefaultQuery("include_zero_balances", "false") == "true"
    // Placeholder dataset; integrate with real balances later
    wallets := []gin.H{
        {"wallet_id": 24, "pair_id": 20, "symbol": "USDT", "name": "Tether USD", "decimals": 6, "balance": "5000.000000", "balance_usd": "5000.00", "price_usd": "1.00"},
        {"wallet_id": 25, "pair_id": 1, "symbol": "BTC", "name": "Bitcoin", "decimals": 8, "balance": "0.05000000", "balance_usd": "5000.00", "price_usd": "100000.00"},
    }
    if !includeZero {
        // all have balances in placeholder
    }
    c.JSON(200, gin.H{
        "wallets": wallets,
        "total_balance_usd": "10000.00",
    })
}

func (r *APIRouter) GetSettings(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var settings models.Settings
	if err := db.Where("user_id = ?", user.ID).First(&settings).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch settings"})
		return
	}

    // Respond flattened per spec
    c.JSON(200, gin.H{
        "theme":            settings.Theme,
        "language":         settings.Language,
        "notifications":    settings.Notifications,
        "email_alerts":     settings.EmailAlerts,
        "sms_alerts":       settings.SmsAlerts,
        "two_factor_auth":  settings.TwoFactorAuth,
        "risk_management":  settings.RiskManagement,
        "max_leverage":     settings.MaxLeverage,
        "auto_close_trades": settings.AutoCloseTrades,
    })
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
        "theme":            req.Theme,
        "language":         req.Language,
        "notifications":    req.Notifications,
        "email_alerts":     req.EmailAlerts,
        "sms_alerts":       req.SmsAlerts,
        "two_factor_auth":  req.TwoFactorAuth,
        "risk_management":  req.RiskManagement,
        "max_leverage":     req.MaxLeverage,
        "auto_close_trades": req.AutoCloseTrades,
    })
}

func (r *APIRouter) GetLeverage(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
    
    c.JSON(200, gin.H{
        "leverage": user.Leverage,
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
        "leverage": req.Leverage,
    })
}
