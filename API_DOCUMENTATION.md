# Trader API Documentation (KYC-First Wallet Auth)

## Base URL
```
https://trade.cradlevoices.com/api/v1/
```
Local development:
```
http://localhost:8080/api/v1/
```

## Authentication
Include JWT in header:
```
Authorization: Bearer <token>
```

### Authentication & KYC

#### Request Challenge Message
```http
POST /auth/wallet/challenge
Content-Type: application/json

{
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
}
```

#### Verify Signature & Get Token
```http
POST /auth/wallet/verify
Content-Type: application/json

{
  "challenge_id": "chall_abc123xyz",
  "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "signature": "0x8f3d2c1b..."
}
```

Response (example):
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<refresh-jwt>",
  "expires_in": 3600,
  "user": {
    "user_id": 1,
    "wallet_address": "0x742d...",
    "is_new_user": true,
    "kyc_status": "not_submitted",
    "can_trade": false,
    "created_at": "2025-10-01T12:00:00Z"
  }
}
```

#### Refresh Token
```http
POST /auth/token/refresh
Content-Type: application/json

{ "refresh_token": "<refresh-jwt>" }
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer <token>
```

### KYC

#### Submit KYC Documents (pending implementation)
```http
POST /kyc/submit (multipart/form-data)
Authorization: Bearer <token>
```

#### Get KYC Status (pending implementation)
```http
GET /kyc/status
Authorization: Bearer <token>
```

#### Get KYC History (pending implementation)
```http
GET /kyc/history
Authorization: Bearer <token>
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

{ "first_name": "John", "last_name": "Doe" }
```

#### Get Platform Activities
```http
GET /user/platform-activities
Authorization: Bearer <token>
```

### Wallet Operations (pending implementation)

```http
GET /wallet/balances
GET /wallet/get-wallets
POST /wallet/deposit
```

### Trading

#### Get User Accounts
```http
GET /trading/accounts
Authorization: Bearer <token>
```

#### Get Orders
```http
GET /trading/orders
Authorization: Bearer <token>
```

#### Create Order
```http
POST /trading/orders
Authorization: Bearer <token>
Content-Type: application/json
```

#### Get Profit Statistics
```http
GET /trading/profit-statistics
Authorization: Bearer <token>
```

### Market Data

#### Get Trading Pairs
```http
GET /market/trading-pairs
Authorization: Bearer <token>
```

#### Get Price Data (pending implementation)
```http
GET /market/price-data/{pair_id}
Authorization: Bearer <token>
```

#### Get Market Overview (pending implementation)
```http
GET /market/overview
Authorization: Bearer <token>
```

### Settings & Security

#### Get/Update Settings
```http
GET /settings/
PUT /settings/
Authorization: Bearer <token>
```

#### Get/Update Security (pending implementation)
```http
GET /security
PUT /security
Authorization: Bearer <token>
```

#### Get/Update Leverage
```http
GET /leverage/
PUT /leverage/
Authorization: Bearer <token>
```

## Error Responses
```json
{ "error": "message" }
```

Common HTTP status codes:
- 200 Success
- 201 Created
- 400 Bad Request
- 401 Unauthorized
- 404 Not Found
- 429 Rate Limit Exceeded
- 500 Internal Server Error

## Health Check
```http
GET /health
```
Response:
```json
{ "status": "ok", "message": "Trader API is running" }
```
