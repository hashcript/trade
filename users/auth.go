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
