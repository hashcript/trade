package users

import (
	"net/http"

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
        Address string `json:"address" binding:"required"`
    }
    if err := database.Bind(c, &req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
        return
    }

    resp, err := h.authService.CreateWalletChallenge(req.Address)
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

	userResponse := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		Balance:   user.Balance,
		Leverage:  user.Leverage,
		RiskLevel: user.RiskLevel,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	c.JSON(http.StatusOK, userResponse)
}

// UpdateProfile updates the current user's profile
func (h *UserHandlers) UpdateProfile(c *gin.Context) {
	user, err := h.authService.GetUserFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req struct {
        FirstName string  `json:"first_name"`
        LastName  string  `json:"last_name"`
		RiskLevel string  `json:"risk_level"`
		Leverage  int     `json:"leverage"`
	}

	if err := database.Bind(c, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": database.NewValidatorError(err)})
		return
	}

	db := database.GetConnection()

    // Disallow first_name and last_name updates per spec
    if req.FirstName != "" || req.LastName != "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Updating first_name and last_name is not allowed"})
        return
    }

    // Update user fields (allowed subset)
	updates := make(map[string]interface{})
	if req.RiskLevel != "" {
		updates["risk_level"] = req.RiskLevel
	}
	if req.Leverage > 0 {
		updates["leverage"] = req.Leverage
	}

	if err := db.Model(user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	// Refresh user data
	db.First(user, user.ID)

	userResponse := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		Balance:   user.Balance,
		Leverage:  user.Leverage,
		RiskLevel: user.RiskLevel,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile updated successfully",
		"user":    userResponse,
	})
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
