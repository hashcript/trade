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
	FirstName string         `json:"first_name" gorm:"type:varchar(100)"`
	LastName  string         `json:"last_name" gorm:"type:varchar(100)"`
	IsActive  bool           `json:"is_active" gorm:"default:true"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`

	// Wallet authentication
	WalletAddress string `json:"wallet_address" gorm:"type:varchar(100);index"`

	// Trading related fields
	Balance    float64 `json:"balance" gorm:"default:0"`
	Leverage   int     `json:"leverage" gorm:"default:1"`
	RiskLevel  string  `json:"risk_level" gorm:"type:varchar(20);default:medium"` // low, medium, high

    // KYC related fields
    IsNewUser      bool       `json:"is_new_user" gorm:"-"`
    KYCStatus      string     `json:"kyc_status" gorm:"type:varchar(20);default:not_submitted"` // not_submitted, pending, approved, rejected
    KYCVerifiedAt  *time.Time `json:"kyc_verified_at"`
    KYCSubmittedAt *time.Time `json:"kyc_submitted_at"`
    KYCRejectedAt  *time.Time `json:"kyc_rejected_at"`
    KYCRejection   string     `json:"rejection_reason" gorm:"type:varchar(255)"`
    
    // Additional KYC fields from OCR
    DateOfBirth    *time.Time `json:"date_of_birth"`
    Nationality    string     `json:"nationality" gorm:"type:varchar(10)"`
    DocumentType   string     `json:"document_type" gorm:"type:varchar(50)"`
    DocumentNumber string     `json:"document_number" gorm:"type:varchar(50)"`
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
	UserID        string     `json:"user_id"`
	WalletAddress string     `json:"wallet_address,omitempty"`
	IsNewUser     bool       `json:"is_new_user"`
	KYCStatus     string     `json:"kyc_status"`
	KYCRequired   bool       `json:"kyc_required,omitempty"`
	KYCVerifiedAt *time.Time `json:"kyc_verified_at,omitempty"`
	KYCSubmittedAt *time.Time `json:"kyc_submitted_at,omitempty"`
	KYCRejectedAt *time.Time `json:"kyc_rejected_at,omitempty"`
	RejectionReason string   `json:"rejection_reason,omitempty"`
	CanResubmit   bool       `json:"can_resubmit,omitempty"`
	FirstName     *string    `json:"first_name"`
	LastName      *string    `json:"last_name"`
	DateOfBirth   *time.Time `json:"date_of_birth,omitempty"`
	Nationality   string     `json:"nationality,omitempty"`
	DocumentType  string     `json:"document_type,omitempty"`
	DocumentNumber string    `json:"document_number,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	CanTrade      bool       `json:"can_trade"`
}

type AuthResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}
