package users

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"com.trader/database"
	"com.trader/models"
)

type UserHandlers struct {
	authService *AuthService
}

func NewUserHandlers() *UserHandlers {
	return &UserHandlers{
		authService: NewAuthService(),
	}
}

// Register handles user registration
func (h *UserHandlers) Register(c *gin.Context) {
	var req models.UserRegisterRequest
	if err := database.Bind(c, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	user, err := h.authService.RegisterUser(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user":    user,
	})
}

// Login handles user login
func (h *UserHandlers) Login(c *gin.Context) {
	var req models.UserLoginRequest
	if err := database.Bind(c, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	authResponse, err := h.authService.LoginUser(&req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, authResponse)
}

// Wallet auth: request challenge
func (h *UserHandlers) RequestWalletChallenge(c *gin.Context) {
    var req struct{
        WalletAddress string `json:"wallet_address" binding:"required"`
    }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
        return
    }

    resp, err := h.authService.CreateWalletChallenge(req.WalletAddress)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, resp)
}

// Wallet auth: verify signature
func (h *UserHandlers) VerifyWalletSignature(c *gin.Context) {
    var req struct{
        ChallengeID string `json:"challenge_id" binding:"required"`
        Address string `json:"address" binding:"required"`
        Signature string `json:"signature" binding:"required"`
    }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
        return
    }

    resp, err := h.authService.VerifyWalletChallenge(c, req.ChallengeID, req.Address, req.Signature)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, resp)
}

// Token refresh
func (h *UserHandlers) RefreshToken(c *gin.Context) {
    var req struct{ RefreshToken string `json:"refresh_token" binding:"required"` }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
        return
    }
    resp, err := h.authService.RefreshAccessToken(req.RefreshToken)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, resp)
}

// Logout endpoint (stateless placeholder)
func (h *UserHandlers) Logout(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// GetProfile returns the current user's profile
func (h *UserHandlers) GetProfile(c *gin.Context) {
	user, err := h.authService.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"user_id":     fmt.Sprintf("usr_%d", user.ID),
		"kyc_status":  user.KYCStatus,
		"created_at":  user.CreatedAt.Format(time.RFC3339),
		"can_trade":   user.KYCStatus == "approved",
	}

	// Add KYC-specific fields based on status
	if user.KYCStatus == "approved" {
		response["kyc_verified_at"] = user.KYCVerifiedAt.Format(time.RFC3339)
		response["first_name"] = user.FirstName
		response["last_name"] = user.LastName
		if user.DateOfBirth != nil {
			response["date_of_birth"] = user.DateOfBirth.Format("2006-01-02")
		}
		response["nationality"] = user.Nationality
		response["document_type"] = user.DocumentType
		response["document_number"] = user.DocumentNumber
	} else if user.KYCStatus == "not_submitted" {
		response["kyc_required"] = true
		response["first_name"] = nil
		response["last_name"] = nil
	} else {
		response["first_name"] = nil
		response["last_name"] = nil
	}

	c.JSON(http.StatusOK, response)
}

// UpdateProfile updates the current user's profile
func (h *UserHandlers) UpdateProfile(c *gin.Context) {
	user, err := h.authService.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req struct {
        FirstName *string `json:"first_name"`
        LastName  *string `json:"last_name"`
	}

	if err := database.Bind(c, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	db := database.GetConnection()

    // Update user fields
	updates := make(map[string]interface{})
	if req.FirstName != nil {
		updates["first_name"] = *req.FirstName
	}
	if req.LastName != nil {
		updates["last_name"] = *req.LastName
	}

	if err := db.Model(user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	// Refresh user data
	db.First(user, user.ID)

	response := gin.H{
		"user_id":     fmt.Sprintf("usr_%d", user.ID),
		"kyc_status":  user.KYCStatus,
		"created_at":  user.CreatedAt.Format(time.RFC3339),
		"can_trade":   user.KYCStatus == "approved",
	}

	// Add KYC-specific fields based on status
	if user.KYCStatus == "approved" {
		response["kyc_verified_at"] = user.KYCVerifiedAt.Format(time.RFC3339)
		response["first_name"] = user.FirstName
		response["last_name"] = user.LastName
		if user.DateOfBirth != nil {
			response["date_of_birth"] = user.DateOfBirth.Format("2006-01-02")
		}
		response["nationality"] = user.Nationality
		response["document_type"] = user.DocumentType
		response["document_number"] = user.DocumentNumber
	} else {
		response["first_name"] = user.FirstName
		response["last_name"] = user.LastName
	}

	c.JSON(http.StatusOK, response)
}

// AuthMiddleware validates JWT tokens
func (h *UserHandlers) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := h.authService.GetUserFromToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}
