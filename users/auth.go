package users

import (
	"errors"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"com.trader/database"
	"com.trader/models"
)

type AuthService struct{}

func NewAuthService() *AuthService {
	return &AuthService{}
}

type WalletChallengeResponse struct {
    ChallengeID string `json:"challenge_id"`
    Message     string `json:"message"`
    ExpiresAt   string `json:"expires_at"`
}

type VerifyWalletResponse struct {
    AccessToken  string                 `json:"access_token"`
    RefreshToken string                 `json:"refresh_token"`
    ExpiresIn    int                    `json:"expires_in"`
    User         map[string]interface{} `json:"user"`
}

// HashPassword hashes a password using bcrypt
func (a *AuthService) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPassword compares a password with its hash
func (a *AuthService) CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// GenerateToken generates a JWT token for a user
func (a *AuthService) GenerateToken(user *models.User) (string, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key" // Default for development
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 days
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func (a *AuthService) generateRefreshToken(user *models.User) (string, error) {
    // For simplicity use same signing but different claim
    jwtSecret := os.Getenv("JWT_SECRET")
    if jwtSecret == "" {
        jwtSecret = "your-secret-key"
    }
    claims := jwt.MapClaims{
        "user_id": user.ID,
        "typ":     "refresh",
        "exp":     time.Now().Add(time.Hour * 24 * 30).Unix(),
        "iat":     time.Now().Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(jwtSecret))
}

// ValidateToken validates a JWT token
func (a *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-secret-key" // Default for development
	}

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(jwtSecret), nil
	})
}

// RegisterUser creates a new user
func (a *AuthService) RegisterUser(req *models.UserRegisterRequest) (*models.UserResponse, error) {
	db := database.GetConnection()

	// Check if user already exists
	var existingUser models.User
	if err := db.Where("email = ? OR username = ?", req.Email, req.Username).First(&existingUser).Error; err == nil {
		return nil, errors.New("user already exists with this email or username")
	}

	// Hash password
	hashedPassword, err := a.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := models.User{
		Email:     req.Email,
		Username:  req.Username,
		Password:  hashedPassword,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Balance:   10000, // Default starting balance
		Leverage:  1,
		RiskLevel: "medium",
		IsActive:  true,
	}

	if err := db.Create(&user).Error; err != nil {
		return nil, err
	}

	// Create default account
	account := models.Account{
		UserID:      user.ID,
		AccountType: "demo",
		Balance:     10000,
		Equity:      10000,
		IsActive:    true,
	}

	if err := db.Create(&account).Error; err != nil {
		return nil, err
	}

	// Create default settings
	settings := models.Settings{
		UserID:         user.ID,
		Theme:          "light",
		Language:       "en",
		Notifications:  true,
		EmailAlerts:    true,
		RiskManagement: "medium",
		MaxLeverage:    10,
	}

	if err := db.Create(&settings).Error; err != nil {
		return nil, err
	}

	return &models.UserResponse{
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
	}, nil
}

// LoginUser authenticates a user
func (a *AuthService) LoginUser(req *models.UserLoginRequest) (*models.AuthResponse, error) {
	db := database.GetConnection()

	var user models.User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	if err := a.CheckPassword(req.Password, user.Password); err != nil {
		return nil, errors.New("invalid credentials")
	}

	token, err := a.GenerateToken(&user)
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		Token: token,
		User: models.UserResponse{
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
		},
	}, nil
}

// GetUserFromToken extracts user from JWT token
func (a *AuthService) GetUserFromToken(c *gin.Context) (*models.User, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, errors.New("authorization header required")
	}

	tokenString := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	}

	token, err := a.ValidateToken(tokenString)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, errors.New("invalid user ID in token")
	}

	db := database.GetConnection()
	var user models.User
	if err := db.First(&user, uint(userID)).Error; err != nil {
		return nil, errors.New("user not found")
	}

	return &user, nil
}

// Wallet-based auth: create challenge
func (a *AuthService) CreateWalletChallenge(walletAddress string) (*WalletChallengeResponse, error) {
    db := database.GetConnection()
    nonce := randomHex(16)
    challengeID := randomHex(12)
    now := time.Now().UTC()
    expires := now.Add(10 * time.Minute)

    message := "Sign this message to authenticate:\n\nWallet: " + walletAddress + "\nNonce: " + nonce + "\nTimestamp: " + now.Format(time.RFC3339)

    challenge := models.AuthChallenge{
        ChallengeID:  challengeID,
        WalletAddress: walletAddress,
        Message:      message,
        Nonce:        nonce,
        ExpiresAt:    expires,
    }
    if err := db.Create(&challenge).Error; err != nil {
        return nil, err
    }

    return &WalletChallengeResponse{
        ChallengeID: challengeID,
        Message:     message,
        ExpiresAt:   expires.Format(time.RFC3339),
    }, nil
}

// Wallet-based auth: verify challenge signature (signature verification stub)
func (a *AuthService) VerifyWalletChallenge(c *gin.Context, challengeID, walletAddress, signature string) (*VerifyWalletResponse, error) {
    db := database.GetConnection()

    var challenge models.AuthChallenge
    if err := db.Where("challenge_id = ? AND wallet_address = ?", challengeID, walletAddress).First(&challenge).Error; err != nil {
        return nil, errors.New("invalid challenge")
    }
    if time.Now().After(challenge.ExpiresAt) {
        return nil, errors.New("challenge expired")
    }

    // TODO: verify signature properly against walletAddress
    if signature == "" {
        return nil, errors.New("invalid signature")
    }

    // Upsert user by wallet address
    var user models.User
    if err := db.Where("wallet_address = ?", walletAddress).First(&user).Error; err != nil {
        // Create minimal user for wallet login
        user = models.User{WalletAddress: walletAddress, IsActive: true}
        if err := db.Create(&user).Error; err != nil {
            return nil, err
        }
        // Create default demo account and settings
        db.Create(&models.Account{UserID: user.ID, AccountType: "demo", Balance: 10000, Equity: 10000, IsActive: true})
        db.Create(&models.Settings{UserID: user.ID, Theme: "light", Language: "en", Notifications: true, EmailAlerts: true, RiskManagement: "medium", MaxLeverage: 10})
    }

    access, err := a.GenerateToken(&user)
    if err != nil {
        return nil, err
    }
    refresh, err := a.generateRefreshToken(&user)
    if err != nil {
        return nil, err
    }

    // Compose user payload per KYC status
    userPayload := map[string]interface{}{
        "user_id":        user.ID,
        "wallet_address": user.WalletAddress,
        "is_new_user":    false,
        "kyc_status":     user.KYCStatus,
        "can_trade":      user.KYCStatus == "approved",
        "created_at":     user.CreatedAt.Format(time.RFC3339),
    }
    if user.KYCVerifiedAt != nil {
        userPayload["kyc_verified_at"] = user.KYCVerifiedAt.Format(time.RFC3339)
    }

    // If new user (no KYC yet)
    if user.KYCStatus == "" || user.KYCStatus == "not_submitted" {
        userPayload["is_new_user"] = true
        userPayload["kyc_required"] = true
        userPayload["kyc_status"] = "not_submitted"
    }

    return &VerifyWalletResponse{
        AccessToken:  access,
        RefreshToken: refresh,
        ExpiresIn:    3600,
        User:         userPayload,
    }, nil
}

// Refresh access token using refresh token
func (a *AuthService) RefreshAccessToken(refreshToken string) (map[string]interface{}, error) {
    token, err := a.ValidateToken(refreshToken)
    if err != nil {
        return nil, errors.New("invalid refresh token")
    }
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || !token.Valid || claims["typ"] != "refresh" {
        return nil, errors.New("invalid refresh token")
    }
    userIDFloat, ok := claims["user_id"].(float64)
    if !ok {
        return nil, errors.New("invalid refresh token payload")
    }
    db := database.GetConnection()
    var user models.User
    if err := db.First(&user, uint(userIDFloat)).Error; err != nil {
        return nil, errors.New("user not found")
    }
    access, err := a.GenerateToken(&user)
    if err != nil {
        return nil, err
    }
    return map[string]interface{}{"access_token": access, "expires_in": 3600}, nil
}

// randomHex returns a random hex string of n bytes
func randomHex(n int) string {
    const hex = "0123456789abcdef"
    b := make([]byte, n)
    // simple pseudo-random; replace with crypto/rand in production
    now := time.Now().UnixNano()
    for i := range b {
        now = now*1664525 + 1013904223
        b[i] = hex[(now>>8)&0x0f]
    }
    return string(b)
}
