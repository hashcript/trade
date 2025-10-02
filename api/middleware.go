package api

import (
	"fmt"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// helper formatting functions reused by handlers
func formatAmount(v float64) string {
    return fmt.Sprintf("%.2f", v)
}

// CORSMiddleware sets up CORS for frontend communication
func CORSMiddleware() gin.HandlerFunc {
	config := cors.Config{
		AllowAllOrigins:  true, // Allow all origins
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	return cors.New(config)
}

// ErrorHandler handles global errors
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			c.JSON(c.Writer.Status(), gin.H{
				"error": err.Error(),
			})
		}
	}
}

// LoggerMiddleware logs requests
func LoggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// RateLimitMiddleware implements basic rate limiting
func RateLimitMiddleware() gin.HandlerFunc {
	// Simple in-memory rate limiting
	requests := make(map[string][]time.Time)
	
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()
		
		// Clean old requests (older than 1 minute)
		if timestamps, exists := requests[ip]; exists {
			var validTimestamps []time.Time
			for _, ts := range timestamps {
				if now.Sub(ts) < time.Minute {
					validTimestamps = append(validTimestamps, ts)
				}
			}
			requests[ip] = validTimestamps
		}
		
		// Check rate limit (100 requests per minute)
		if len(requests[ip]) >= 100 {
			c.JSON(429, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		
		// Add current request
		requests[ip] = append(requests[ip], now)
		c.Next()
	}
}
