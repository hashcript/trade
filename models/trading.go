package models

import (
	"time"

	"gorm.io/gorm"
)

type Transaction struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	UserID      uint           `json:"user_id" gorm:"not null;index"`
	AccountID   uint           `json:"account_id" gorm:"not null;index"`
	PairID      uint           `json:"pair_id" gorm:"not null"`
	PairSymbol  string         `json:"pair_symbol" gorm:"type:varchar(20);not null"`
	Type        string         `json:"type" gorm:"type:varchar(20);not null"` // long, short
	Amount      float64        `json:"amount" gorm:"not null"`
	AmountUSDT  float64        `json:"amount_usdt" gorm:"not null"`
	Price       float64        `json:"price" gorm:"not null"`
	EntryPrice  float64        `json:"entry_price" gorm:"not null"`
	TotalValue  float64        `json:"total_value" gorm:"not null"`
	Leverage    int            `json:"leverage" gorm:"default:1"`
	DeliveryTime string        `json:"delivery_time" gorm:"type:varchar(10)"`
	PriceRange  int            `json:"price_range" gorm:"default:0"`
	ProfitLoss  float64        `json:"profit_loss" gorm:"default:0"`
	Status      string         `json:"status" gorm:"type:varchar(20);default:open"` // open, completed, cancelled
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Relations
	User    User    `json:"user" gorm:"foreignKey:UserID;references:ID"`
	Account Account `json:"account" gorm:"foreignKey:AccountID;references:ID"`
}

type Account struct {
	ID           uint           `json:"id" gorm:"primaryKey"`
	UserID       uint           `json:"user_id" gorm:"not null;index"`
	AccountType  string         `json:"account_type" gorm:"type:varchar(20);not null"` // demo, live
	Balance      float64        `json:"balance" gorm:"default:0"`
	Equity       float64        `json:"equity" gorm:"default:0"`
	Margin       float64        `json:"margin" gorm:"default:0"`
	FreeMargin   float64        `json:"free_margin" gorm:"default:0"`
	MarginLevel  float64        `json:"margin_level" gorm:"default:0"`
	IsActive     bool           `json:"is_active" gorm:"default:true"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Relations
	User User `json:"user" gorm:"foreignKey:UserID;references:ID"`
}

type TradingPair struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Symbol      string         `json:"symbol" gorm:"type:varchar(20);uniqueIndex;not null"` // BTC/USD
	BaseAsset   string         `json:"base_asset" gorm:"type:varchar(20);not null"` // BTC
	QuoteAsset  string         `json:"quote_asset" gorm:"type:varchar(20);not null"` // USD
	MinQty      float64        `json:"min_qty" gorm:"default:0.001"`
	MaxQty      float64        `json:"max_qty" gorm:"default:1000"`
	StepSize    float64        `json:"step_size" gorm:"default:0.001"`
	MinPrice    float64        `json:"min_price" gorm:"default:0.01"`
	MaxPrice    float64        `json:"max_price" gorm:"default:1000000"`
	TickSize    float64        `json:"tick_size" gorm:"default:0.01"`
	IsActive    bool           `json:"is_active" gorm:"default:true"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

type ProfitStatistics struct {
	ID                uint           `json:"id" gorm:"primaryKey"`
	UserID            uint           `json:"user_id" gorm:"not null;index"`
	Date              time.Time      `json:"date" gorm:"not null"`
	TotalTrades       int            `json:"total_trades" gorm:"default:0"`
	WinningTrades     int            `json:"winning_trades" gorm:"default:0"`
	LosingTrades      int            `json:"losing_trades" gorm:"default:0"`
	WinRate           float64        `json:"win_rate" gorm:"default:0"`
	TotalProfit       float64        `json:"total_profit" gorm:"default:0"`
	TotalLoss         float64        `json:"total_loss" gorm:"default:0"`
	NetProfit         float64        `json:"net_profit" gorm:"default:0"`
	AverageWin        float64        `json:"average_win" gorm:"default:0"`
	AverageLoss       float64        `json:"average_loss" gorm:"default:0"`
	ProfitFactor      float64        `json:"profit_factor" gorm:"default:0"`
	MaxDrawdown       float64        `json:"max_drawdown" gorm:"default:0"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Relations
	User User `json:"user" gorm:"foreignKey:UserID;references:ID"`
}

type PlatformActivity struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	UserID      uint           `json:"user_id" gorm:"not null;index"`
	Activity    string         `json:"activity" gorm:"type:varchar(50);not null"` // login, logout, trade, deposit, etc.
	Description string         `json:"description" gorm:"type:varchar(255)"`
	IPAddress   string         `json:"ip_address" gorm:"type:varchar(45)"` // IPv6 support
	UserAgent   string         `json:"user_agent" gorm:"type:varchar(500)"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Relations
	User User `json:"user" gorm:"foreignKey:UserID;references:ID"`
}

type Settings struct {
	ID              uint           `json:"id" gorm:"primaryKey"`
	UserID          uint           `json:"user_id" gorm:"not null;index"`
	Theme           string         `json:"theme" gorm:"type:varchar(20);default:light"` // light, dark
	Language        string         `json:"language" gorm:"type:varchar(10);default:en"`
	Notifications   bool           `json:"notifications" gorm:"default:true"`
	EmailAlerts     bool           `json:"email_alerts" gorm:"default:true"`
	SmsAlerts       bool           `json:"sms_alerts" gorm:"default:false"`
	TwoFactorAuth   bool           `json:"two_factor_auth" gorm:"default:false"`
	RiskManagement  string         `json:"risk_management" gorm:"type:varchar(20);default:medium"` // low, medium, high
	MaxLeverage     int            `json:"max_leverage" gorm:"default:10"`
	AutoCloseTrades bool           `json:"auto_close_trades" gorm:"default:false"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Relations
	User User `json:"user" gorm:"foreignKey:UserID;references:ID"`
}

// KYCSubmission represents a user's KYC submission lifecycle
type KYCSubmission struct {
    ID          uint           `json:"kyc_submission_id" gorm:"primaryKey"`
    UserID      uint           `json:"user_id" gorm:"not null;index"`
    Status      string         `json:"status" gorm:"type:varchar(20);default:pending"` // pending, processing, manual_review, approved, rejected
    DocumentType string        `json:"document_type" gorm:"type:varchar(50)"`
    RejectionReason string     `json:"rejection_reason" gorm:"type:varchar(255)"`
    SubmittedAt time.Time      `json:"submitted_at"`
    ProcessedAt *time.Time     `json:"processed_at"`
    ApprovedAt  *time.Time     `json:"approved_at"`
    RejectedAt  *time.Time     `json:"rejected_at"`
    CreatedAt   time.Time      `json:"created_at"`
    UpdatedAt   time.Time      `json:"updated_at"`
    DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`

    User User `json:"user" gorm:"foreignKey:UserID;references:ID"`
}

// AuthChallenge stores wallet sign-in challenges
type AuthChallenge struct {
    ID           uint      `json:"-" gorm:"primaryKey"`
    ChallengeID  string    `json:"challenge_id" gorm:"type:varchar(64);uniqueIndex"`
    WalletAddress string   `json:"wallet_address" gorm:"type:varchar(100);index"`
    Message      string    `json:"message" gorm:"type:text"`
    Nonce        string    `json:"nonce" gorm:"type:varchar(64)"`
    ExpiresAt    time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
