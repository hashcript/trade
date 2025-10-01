# Trader API Documentation

## Base URL
```
http://localhost:8080/api/v1
```

## Authentication
The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## API Endpoints

### Authentication

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "password123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "is_active": true,
    "balance": 10000,
    "leverage": 1,
    "risk_level": "medium",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

#### Login User
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "first_name": "John",
    "last_name": "Doe",
    "is_active": true,
    "balance": 10000,
    "leverage": 1,
    "risk_level": "medium",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### User Management

#### Get User Profile
```http
GET /user/profile
Authorization: Bearer <token>
```

#### Update User Profile
```http
PUT /user/profile
Authorization: Bearer <token>
Content-Type: application/json

{
  "first_name": "John",
  "last_name": "Doe",
  "risk_level": "high",
  "leverage": 5
}
```

### Trading

#### Get User Accounts
```http
GET /trading/accounts
Authorization: Bearer <token>
```

**Response:**
```json
{
  "accounts": [
    {
      "id": 1,
      "user_id": 1,
      "account_type": "demo",
      "balance": 10000,
      "equity": 10000,
      "margin": 0,
      "free_margin": 10000,
      "margin_level": 0,
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### Get Transactions
```http
GET /trading/transactions
Authorization: Bearer <token>
```

**Response:**
```json
{
  "transactions": [
    {
      "id": 1,
      "user_id": 1,
      "type": "buy",
      "symbol": "BTC/USD",
      "amount": 0.1,
      "price": 50000,
      "total_value": 5000,
      "leverage": 1,
      "status": "completed",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### Create Transaction
```http
POST /trading/transactions
Authorization: Bearer <token>
Content-Type: application/json

{
  "type": "buy",
  "symbol": "BTC/USD",
  "amount": 0.1,
  "price": 50000,
  "leverage": 1
}
```

#### Get Profit Statistics
```http
GET /trading/profit-statistics
Authorization: Bearer <token>
```

#### Get Platform Activities
```http
GET /trading/platform-activities
Authorization: Bearer <token>
```

#### Get Trading Pairs
```http
GET /trading/trading-pairs
Authorization: Bearer <token>
```

### Settings

#### Get User Settings
```http
GET /settings/
Authorization: Bearer <token>
```

#### Update User Settings
```http
PUT /settings/
Authorization: Bearer <token>
Content-Type: application/json

{
  "theme": "dark",
  "language": "en",
  "notifications": true,
  "email_alerts": true,
  "sms_alerts": false,
  "two_factor_auth": false,
  "risk_management": "high",
  "max_leverage": 20,
  "auto_close_trades": false
}
```

### Leverage

#### Get Current Leverage
```http
GET /leverage/
Authorization: Bearer <token>
```

#### Update Leverage
```http
PUT /leverage/
Authorization: Bearer <token>
Content-Type: application/json

{
  "leverage": 10
}
```

## Error Responses

All error responses follow this format:

```json
{
  "error": "Error message description"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `404` - Not Found
- `429` - Rate Limit Exceeded
- `500` - Internal Server Error

## Rate Limiting

The API implements rate limiting:
- 100 requests per minute per IP address
- Rate limit exceeded returns HTTP 429

## CORS

The API supports CORS for the following origins:
- `http://localhost:3000`
- `http://localhost:3001`
- `http://127.0.0.1:3000`
- `http://127.0.0.1:3001`

## Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "message": "Trader API is running"
}
```
