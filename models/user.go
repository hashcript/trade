package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
    Email     string         `json:"email" gorm:"type:varchar(255);uniqueIndex;"`
    Username  string         `json:"username" gorm:"type:varchar(50);uniqueIndex;"`
    Password  string         `json:"-" gorm:"type:varchar(255);"`
	FirstName string         `json:"first_name" gorm:"type:varchar(100)" validate:"required"`
	LastName  string         `json:"last_name" gorm:"type:varchar(100)" validate:"required"`
	IsActive  bool           `json:"is_active" gorm:"default:true"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Trading related fields
	Balance    float64 `json:"balance" gorm:"default:0"`
	Leverage   int     `json:"leverage" gorm:"default:1"`
	RiskLevel  string  `json:"risk_level" gorm:"type:varchar(20);default:medium"` // low, medium, high

    // Wallet/KYC related fields
    WalletAddress  string     `json:"wallet_address" gorm:"type:varchar(100);uniqueIndex"`
    IsNewUser      bool       `json:"is_new_user" gorm:"-"`
    KYCStatus      string     `json:"kyc_status" gorm:"type:varchar(20);default:not_submitted"` // not_submitted, pending, approved, rejected
    KYCVerifiedAt  *time.Time `json:"kyc_verified_at"`
    KYCSubmittedAt *time.Time `json:"kyc_submitted_at"`
    KYCRejectedAt  *time.Time `json:"kyc_rejected_at"`
    KYCRejection   string     `json:"rejection_reason" gorm:"type:varchar(255)"`
}

type UserLoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type UserRegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username" validate:"required,min=3,max=20"`
	Password  string `json:"password" validate:"required,min=6"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

type UserResponse struct {
	ID        uint      `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsActive  bool      `json:"is_active"`
	Balance   float64   `json:"balance"`
	Leverage  int       `json:"leverage"`
	RiskLevel string    `json:"risk_level"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
    // Wallet/KYC additions (used by new endpoints)
    WalletAddress string     `json:"wallet_address,omitempty"`
    KYCStatus     string     `json:"kyc_status,omitempty"`
    KYCVerifiedAt *time.Time `json:"kyc_verified_at,omitempty"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}
