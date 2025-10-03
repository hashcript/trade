package api

import (
    "fmt"
    "time"
    "mime/multipart"
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
				market.GET("/overview", r.GetMarketOverview)
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

	// Get query parameters
	accountID := c.Query("account_id")
	status := c.Query("status")

	query := db.Where("user_id = ?", user.ID)
	
	if accountID != "" {
		query = query.Where("account_id = ?", accountID)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var transactions []models.Transaction
	if err := query.Order("created_at DESC").Limit(50).Find(&transactions).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch transactions"})
		return
	}

	c.JSON(200, gin.H{"orders": transactions})
}

func (r *APIRouter) CreateTransaction(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	var req struct {
		AccountID    uint    `json:"account_id" binding:"required"`
		PairID       uint    `json:"pair_id" binding:"required"`
		Type         string  `json:"type" binding:"required"`
		AmountUSDT   float64 `json:"amount_usdt" binding:"required"`
		Leverage     int     `json:"leverage" binding:"required"`
		DeliveryTime string  `json:"delivery_time" binding:"required"`
		PriceRange   int     `json:"price_range" binding:"required"`
	}

	if err := database.Bind(c, &req); err != nil {
		c.JSON(400, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	// Get trading pair info
	var pair models.TradingPair
	if err := db.First(&pair, req.PairID).Error; err != nil {
		c.JSON(400, gin.H{"error": "Invalid trading pair"})
		return
	}

	// Get account info
	var account models.Account
	if err := db.Where("id = ? AND user_id = ?", req.AccountID, user.ID).First(&account).Error; err != nil {
		c.JSON(400, gin.H{"error": "Invalid account"})
		return
	}

	// Calculate entry price (simplified - in real implementation, this would be current market price)
	entryPrice := 100000.0 // Mock price for BTC/USDT
	if pair.BaseAsset == "ETH" {
		entryPrice = 3500.0
	}

	transaction := models.Transaction{
		UserID:       user.ID,
		AccountID:    req.AccountID,
		PairID:       req.PairID,
		PairSymbol:   pair.Symbol,
		Type:         req.Type,
		Amount:       req.AmountUSDT / entryPrice,
		AmountUSDT:   req.AmountUSDT,
		Price:        entryPrice,
		EntryPrice:   entryPrice,
		TotalValue:   req.AmountUSDT,
		Leverage:     req.Leverage,
		DeliveryTime: req.DeliveryTime,
		PriceRange:   req.PriceRange,
		Status:       "open",
	}

	if err := db.Create(&transaction).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create transaction"})
		return
	}

	c.JSON(201, gin.H{
		"id":             transaction.ID,
		"user_id":        transaction.UserID,
		"account_id":     transaction.AccountID,
		"pair_id":        transaction.PairID,
		"pair_symbol":    transaction.PairSymbol,
		"type":           transaction.Type,
		"amount_usdt":    transaction.AmountUSDT,
		"leverage":       transaction.Leverage,
		"entry_price":    transaction.EntryPrice,
		"delivery_time":  transaction.DeliveryTime,
		"price_range":    transaction.PriceRange,
		"status":         transaction.Status,
		"created_at":     transaction.CreatedAt.Format(time.RFC3339),
	})
}

func (r *APIRouter) GetProfitStatistics(c *gin.Context) {
	user := c.MustGet("user").(*models.User)
	db := database.GetConnection()

	// Get required account_id parameter
	accountID := c.Query("account_id")
	if accountID == "" {
		c.JSON(400, gin.H{"error": "account_id is required"})
		return
	}

	// Get optional date range parameters
	startDate := c.Query("start_date")
	endDate := c.Query("end_date")

	query := db.Where("user_id = ? AND account_id = ?", user.ID, accountID)
	
	if startDate != "" {
		if startTime, err := time.Parse("2006-01-02", startDate); err == nil {
			query = query.Where("created_at >= ?", startTime)
		}
	}
	if endDate != "" {
		if endTime, err := time.Parse("2006-01-02", endDate); err == nil {
			query = query.Where("created_at <= ?", endTime.Add(24*time.Hour))
		}
	}

	var transactions []models.Transaction
	if err := query.Order("created_at ASC").Find(&transactions).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch profit statistics"})
		return
	}

	// Generate mock statistics data (timestamp, profit_usd)
	statistics := [][]interface{}{}
	baseTime := time.Now().Add(-24 * time.Hour)
	profit := 0.0
	
	for i := 0; i < 24; i++ {
		timestamp := baseTime.Add(time.Duration(i) * time.Hour).Unix()
		profit += float64(i*10 - 50) // Mock profit/loss
		statistics = append(statistics, []interface{}{timestamp, profit})
	}

	c.JSON(200, gin.H{
		"account_id":  accountID,
		"statistics": statistics,
	})
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
        case "LTC":
            name = "Litecoin"
            logo = "https://assets.trustwallet.com/blockchains/litecoin/info/logo.png"
            valueUSD = 75
            pct = 1.2
            high = 78
            low = 72
            vol = 15000000
        case "ADA":
            name = "Cardano"
            logo = "https://assets.trustwallet.com/blockchains/cardano/info/logo.png"
            valueUSD = 0.45
            pct = -0.8
            high = 0.47
            low = 0.43
            vol = 25000000
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

// Market overview endpoint
func (r *APIRouter) GetMarketOverview(c *gin.Context) {
    c.JSON(200, gin.H{
        "total_market_cap": "2500000000000.00",
        "total_volume_24h": "125000000000.00",
        "market_change_24h": 1.8,
        "btc_dominance": 52.3,
        "top_gainers": []gin.H{
            {
                "pair_id": 5,
                "symbol": "SOL/USD",
                "percentage_change": 8.5,
            },
        },
        "top_losers": []gin.H{
            {
                "pair_id": 12,
                "symbol": "ADA/USD",
                "percentage_change": -5.2,
            },
        },
    })
}

// Wallet list/address endpoint (stub)
func (r *APIRouter) GetWalletAddresses(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    
    wallets := []gin.H{
        {"wallet_id": 1, "pair_id": 4, "symbol": "BTC", "address": "bc1qxyz...", "network": "Bitcoin"},
        {"wallet_id": 2, "pair_id": 20, "symbol": "USDT", "address": "0xabc123...", "network": "Ethereum (ERC20)"},
    }
    
    c.JSON(200, gin.H{
        "wallets": wallets,
        "user_id": user.ID,
        "count": len(wallets),
    })
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

// KYC submit (handles multipart/form-data with file uploads)
func (r *APIRouter) SubmitKYC(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    db := database.GetConnection()
    
    // Parse multipart form
    form, err := c.MultipartForm()
    if err != nil {
        c.JSON(400, gin.H{"error": "Failed to parse multipart form"})
        return
    }
    
    // Get document type
    documentType := form.Value["document_type"]
    if len(documentType) == 0 {
        c.JSON(400, gin.H{"error": "document_type is required"})
        return
    }
    
    // Get uploaded files
    documentFront := form.File["document_front"]
    if len(documentFront) == 0 {
        c.JSON(400, gin.H{"error": "document_front is required"})
        return
    }
    
    var documentBack []*multipart.FileHeader
    if documentType[0] == "national_id" || documentType[0] == "drivers_license" {
        documentBack = form.File["document_back"]
        if len(documentBack) == 0 {
            c.JSON(400, gin.H{"error": "document_back is required for " + documentType[0]})
            return
        }
    }
    
    // Create KYC submission
    kycSubmission := models.KYCSubmission{
        UserID:       user.ID,
        Status:       "processing",
        DocumentType: documentType[0],
        SubmittedAt:  time.Now().UTC(),
    }
    
    if err := db.Create(&kycSubmission).Error; err != nil {
        c.JSON(500, gin.H{"error": "Failed to submit KYC"})
        return
    }
    
    // Update user KYC status
    if err := db.Model(user).Updates(map[string]interface{}{
        "kyc_status":       "pending",
        "kyc_submitted_at": time.Now().UTC(),
    }).Error; err != nil {
        c.JSON(500, gin.H{"error": "Failed to update user KYC status"})
        return
    }
    
    // Simulate OCR extraction (in real implementation, this would call OCR service)
    ocrData := map[string]interface{}{
        "first_name":       "John",
        "last_name":        "Doe",
        "date_of_birth":    "1990-05-15",
        "nationality":      "US",
        "document_number":  "P12345678",
        "document_expiry":  "2030-05-14",
        "confidence_score": 0.95,
    }
    
    // Update user with OCR data
    if err := db.Model(user).Updates(map[string]interface{}{
        "first_name":     "John",
        "last_name":      "Doe",
        "date_of_birth":  time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC),
        "nationality":    "US",
        "document_type":  documentType[0],
        "document_number": "P12345678",
    }).Error; err != nil {
        c.JSON(500, gin.H{"error": "Failed to update user with OCR data"})
        return
    }
    
    c.JSON(200, gin.H{
        "kyc_submission_id": fmt.Sprintf("kyc_sub_%d", kycSubmission.ID),
        "status":            "processing",
        "submitted_at":      kycSubmission.SubmittedAt.Format(time.RFC3339),
        "estimated_processing_time": "2-24 hours",
        "ocr_extracted_data": ocrData,
        "message": "Documents submitted successfully. We'll review your application and notify you via email.",
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
        "require_pin": settings.TwoFactorAuth,
        "privacy_mode": false,
    })
}

func (r *APIRouter) UpdateSecurity(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    db := database.GetConnection()
    var req struct {
        RequirePin  bool `json:"require_pin"`
        PrivacyMode bool `json:"privacy_mode"`
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
        "require_pin": req.RequirePin,
        "privacy_mode": req.PrivacyMode,
    })
}

// Wallet balances per spec (placeholder)
func (r *APIRouter) GetWalletBalances(c *gin.Context) {
    user := c.MustGet("user").(*models.User)
    includeZero := c.DefaultQuery("include_zero_balances", "false") == "true"
    
    // Placeholder dataset; integrate with real balances later
    wallets := []gin.H{
        {"wallet_id": 24, "pair_id": 20, "symbol": "USDT", "name": "Tether USD", "decimals": 6, "balance": "5000.000000", "balance_usd": "5000.00", "price_usd": "1.00"},
        {"wallet_id": 25, "pair_id": 1, "symbol": "BTC", "name": "Bitcoin", "decimals": 8, "balance": "0.05000000", "balance_usd": "5000.00", "price_usd": "100000.00"},
    }
    
    // Filter out zero balances if requested
    if !includeZero {
        filteredWallets := make([]gin.H, 0)
        for _, wallet := range wallets {
            if balance, ok := wallet["balance"].(string); ok && balance != "0" && balance != "0.000000" && balance != "0.00000000" {
                filteredWallets = append(filteredWallets, wallet)
            }
        }
        wallets = filteredWallets
    }
    
    c.JSON(200, gin.H{
        "wallets": wallets,
        "total_balance_usd": "10000.00",
        "user_id": user.ID,
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
