# Trader API

A modular Go-based trading platform API with JWT authentication, designed for frontend integration.

## Features

- 🔐 JWT-based authentication
- 👤 User management with profiles
- 💰 Trading accounts and transactions
- 📊 Profit statistics and analytics
- ⚙️ User settings and preferences
- 🔄 Leverage management
- 📈 Trading pairs management
- 🛡️ CORS support for frontend integration
- 🚦 Rate limiting
- 📝 Comprehensive API documentation

## Project Structure

```
Trader/
├── api/                    # API routes and middleware
│   ├── middleware.go       # CORS, rate limiting, error handling
│   ├── routes.go          # All API endpoints
│   └── go.mod
├── database/              # Database connection and utilities
│   ├── database.go        # DB connection, validation helpers
│   └── go.mod
├── models/                # Data models
│   ├── user.go           # User and authentication models
│   ├── trading.go        # Trading-related models
│   └── go.mod
├── users/                 # User authentication and management
│   ├── auth.go           # JWT authentication logic
│   ├── handlers.go       # User-related HTTP handlers
│   └── go.mod
├── main.go               # Application entry point
├── config.go             # Configuration management
├── go.mod                # Main module dependencies
├── go.work               # Go workspace configuration
└── API_DOCUMENTATION.md  # Complete API documentation
```

## Prerequisites

- Go 1.21 or higher
- MySQL 5.7 or higher
- Git

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Trader
   ```

2. **Install dependencies:**
   ```bash
   go mod download
   ```

3. **Set up MySQL database:**
   - Create a MySQL database named `task`
   - Update database credentials in `.env` file (see Configuration section)

4. **Environment Configuration:**
   Create a `.env` file in the root directory:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=colls
   DB_PASSWORD=1234
   DB_NAME=task

   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

   # Server Configuration
   PORT=8080
   GIN_MODE=debug

   # CORS Origins (comma-separated)
   CORS_ORIGINS=http://localhost:3000,http://localhost:3001
   ```

## Running the Application

1. **Build the application:**
   ```bash
   go build -o trader .
   ```

2. **Run the application:**
   ```bash
   ./trader
   ```

   Or run directly with Go:
   ```bash
   go run .
   ```

3. **The API will be available at:**
   ```
   http://localhost:8080
   ```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Login user

### User Management
- `GET /api/v1/user/profile` - Get user profile
- `PUT /api/v1/user/profile` - Update user profile

### Trading
- `GET /api/v1/trading/accounts` - Get user accounts
- `GET /api/v1/trading/transactions` - Get user transactions
- `POST /api/v1/trading/transactions` - Create new transaction
- `GET /api/v1/trading/profit-statistics` - Get profit statistics
- `GET /api/v1/trading/platform-activities` - Get platform activities
- `GET /api/v1/trading/trading-pairs` - Get available trading pairs

### Settings
- `GET /api/v1/settings/` - Get user settings
- `PUT /api/v1/settings/` - Update user settings

### Leverage
- `GET /api/v1/leverage/` - Get current leverage
- `PUT /api/v1/leverage/` - Update leverage

### Health Check
- `GET /health` - API health status

## Authentication

The API uses JWT tokens for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Frontend Integration

The API is designed for easy frontend integration:

- **CORS enabled** for common development ports
- **RESTful endpoints** with consistent JSON responses
- **JWT authentication** for secure user sessions
- **Comprehensive error handling** with meaningful error messages
- **Rate limiting** to prevent abuse

## Database Schema

The application automatically creates the following tables:
- `users` - User accounts and profiles
- `transactions` - Trading transactions
- `accounts` - User trading accounts
- `trading_pairs` - Available trading pairs
- `profit_statistics` - Trading performance metrics
- `platform_activities` - User activity logs
- `settings` - User preferences and settings

## Development

### Adding New Endpoints

1. Define models in the `models/` package
2. Create handlers in the appropriate module (e.g., `users/`, `api/`)
3. Add routes in `api/routes.go`
4. Update API documentation

### Testing

```bash
# Run tests
go test ./...

# Run with coverage
go test -cover ./...
```

### Code Style

- Follow Go conventions and best practices
- Use meaningful variable and function names
- Add comments for public functions
- Handle errors appropriately

## Production Deployment

1. **Set production environment variables:**
   - Use strong JWT secret
   - Configure production database
   - Set appropriate CORS origins
   - Enable production Gin mode

2. **Security considerations:**
   - Use HTTPS in production
   - Implement proper logging
   - Set up monitoring
   - Regular security updates

## API Documentation

Complete API documentation is available in `API_DOCUMENTATION.md` with:
- Detailed endpoint descriptions
- Request/response examples
- Error handling information
- Authentication requirements

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]
