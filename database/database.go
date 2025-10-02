package database

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"gorm.io/driver/mysql" // Use the MySQL driver
	"gorm.io/gorm"
)

var DB *gorm.DB

// Open the database and establish the connection
func Init() *gorm.DB {
	// Get database configuration from environment variables
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "3306")
	user := getEnv("DB_USER", "colls")
	password := getEnv("DB_PASSWORD", "Kali@linux003")
	dbname := getEnv("DB_NAME", "trade")
	/*
	

	*/
	

	// Build DSN string
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		user, password, host, port, dbname)

	// Open the database connection.
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database:", err)
	}

	DB = db
	return DB
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Function to get the database connection
func GetConnection() *gorm.DB {
	return DB
}

// Binder
func Bind(c *gin.Context, object interface{}) error {
	binder := binding.Default(c.Request.Method, c.ContentType())
	return c.ShouldBindWith(object, binder)
}

// Return customized error info
type CommonError struct {
	Errors map[string]interface{} `json:"errors"`
}

// Validators

func NewValidatorError(err error) CommonError {
	res := CommonError{}
	res.Errors = make(map[string]interface{})
	errs := err.(validator.ValidationErrors)
	for _, v := range errs {
		res1 := fmt.Sprintf("{%v: %v}", v.Tag(), v.Param())
		fmt.Println(res1)
		if v.Param() != "" {

			res.Errors[v.Field()] = fmt.Sprintf("{%v: %v}", v.Tag(), v.Param())
		} else {
			res.Errors[v.Field()] = fmt.Sprintf("{key: %v}", v.Tag())
		}
	}
	return res
}

// Wrapping error into an object
func NewError(key string, err error) CommonError {
	res := CommonError{}
	res.Errors = make(map[string]interface{})
	res.Errors[key] = err.Error()
	return res
}
