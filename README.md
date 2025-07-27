# User Management System for Rust Web Applications

## Project Overview

This project provides a comprehensive user management system for Rust web applications built with Axum. It includes
robust handlers for user registration, authentication, profile management, and admin operations, along with a flexible
error handling system.

## Key Components

### 1. Authentication System (`auth/`)

The `auth` directory implements a complete authentication and authorization system with several specialized modules:

#### 1.1 Core Authentication (`auth/mod.rs`, `auth/service.rs`, `auth/handlers.rs`)

- **Token-Based Authentication**
    - JWT (JSON Web Tokens) implementation with access and refresh tokens
    - Configurable token expiration and signing algorithms
    - Secure token storage and validation mechanisms

- **Authentication Handlers**
    - Login endpoint with credential validation
    - Token refresh endpoint for session continuation
    - Logout functionality with token invalidation
    - Social authentication integration (OAuth2)

#### 1.2 Multi-Factor Authentication (`auth/mfa/`)

- **TOTP (Time-based One-Time Password)**
    - Implementation of RFC 6238 for time-based authentication codes
    - QR code generation for easy setup with authenticator apps
    - Secure backup codes generation and management

- **Recovery Methods**
    - Backup code validation and one-time usage tracking
    - Device trust mechanisms to reduce MFA friction
    - MFA reset procedures for account recovery

- **MFA Enrollment Workflow**
    - Step-by-step MFA setup process
    - Verification of MFA during setup
    - Ability to enable/disable MFA for accounts

#### 1.3 Password Management (`auth/password/`)

- **Password Validation**
    - Configurable password complexity requirements
    - Common password detection and prevention
    - Secure password hashing using Argon2id with salt

- **Password Reset Flow**
    - Secure token generation for password resets
    - Time-limited reset tokens
    - Email delivery of reset instructions
    - Reset confirmation and notification

- **Password History**
    - Optional tracking of password history to prevent reuse
    - Configurable password rotation policies
    - Password strength assessment

#### 1.4 OAuth Integration (`auth/oauth/`)

- **Provider Integration**
    - Support for common OAuth providers (Google, GitHub, etc.)
    - Standardized provider interface for easy extension
    - Account linking between social and email/password accounts

- **Token Exchange**
    - OAuth token to JWT exchange mechanism
    - User profile extraction from OAuth data
    - Creation of new user accounts from OAuth profiles

#### 1.5 Middleware and Protection (`auth/middleware.rs`)

- **Authentication Middleware**
    - JWT validation middleware for protected routes
    - Role-based access control for fine-grained permissions
    - Rate limiting to prevent brute force attacks

- **Security Features**
    - CSRF protection mechanisms
    - Secure cookie management
    - IP-based request analysis
    - Session management utilities

### 2. User API Handlers (`handlers.rs`)

The `handlers.rs` module implements HTTP handlers for all user-related operations:

- **Authentication & Sessions**
    - User registration
    - Login/logout functionality
    - Token refresh mechanism
    - OAuth integration

- **Profile Management**
    - Retrieving user profiles
    - Updating profile information
    - Password management (change, reset)

- **Admin Functions**
    - User listing with pagination
    - Role assignment
    - User statistics

- **Security Features**
    - Email verification
    - Password reset flows
    - Token-based authentication

Each handler follows a consistent pattern of extracting request data, calling the appropriate service method, and
formatting the response. The handlers are designed to be testable, with a comprehensive test suite included.

### 3. Error Handling System (`error.rs`)

The `error.rs` module provides a flexible and standardized error handling approach:

- **Structured Error Types**
    - Categorized errors (Authentication, Authorization, Validation, etc.)
    - Meaningful error messages and codes
    - Support for detailed validation errors

- **HTTP Integration**
    - Automatic conversion to appropriate HTTP status codes
    - Consistent JSON error response format
    - Client-friendly error details

- **Library Integrations**
    - Conversions from common library errors (sqlx, argon2, jsonwebtoken)
    - Feature-flagged implementations to keep dependencies optional

- **Developer Experience**
    - Factory methods for easy error creation
    - Centralized error logging
    - Comprehensive test coverage

## Authentication Implementation Details

### Token System

The authentication system uses a dual-token approach:

``` rust
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}
```

- **Access Token**: Short-lived token (15-60 minutes) used for API authorization
- **Refresh Token**: Longer-lived token (days/weeks) for obtaining new access tokens

### Multi-Factor Authentication Flow

The MFA system supports multiple authentication methods:

``` rust
pub enum MfaMethod {
    Totp,
    RecoveryCode,
    TrustedDevice,
    // Extensible for future methods
}

pub struct MfaConfiguration {
    pub user_id: Uuid,
    pub enabled: bool,
    pub totp_secret: Option<String>,
    pub recovery_codes: Vec<String>,
    pub last_used: Option<DateTime<Utc>>,
}
```

MFA authentication flow:

1. **User logs in with password**
2. **System detects MFA is enabled**
3. **User is prompted for MFA code**
4. **User provides TOTP or recovery code**
5. **System validates the code and grants full access**

Example of MFA setup:

``` rust
// Generate new TOTP secret
POST /auth/mfa/setup
Authorization: Bearer access_token

// Returns
{
  "status": 200,
  "message": "MFA setup initiated",
  "data": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "data:image/png;base64,iVBORw0KGgo...",
    "recovery_codes": [
      "1234-5678-9012",
      "2345-6789-0123",
      // More codes...
    ]
  }
}

// Verify and enable MFA
POST /auth/mfa/verify
Authorization: Bearer access_token
{
  "code": "123456"
}
```

### Password Management Features

Password management includes several security features:

``` rust
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub prevent_common_passwords: bool,
    pub prevent_password_reuse: Option<usize>,
}

pub struct PasswordResetToken {
    pub token: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}
```

Password reset flow:

1. **User requests password reset**

``` rust
   POST /auth/password/reset-request
   {
     "email": "user@example.com"
   }
```

1. **System generates reset token and sends email**
2. **User submits new password with token**

``` rust
   POST /auth/password/reset
   {
     "token": "reset_token_here",
     "new_password": "new_secure_password"
   }
```

1. **System validates token, updates password, and invalidates token**

### Auth Flow

1. **Registration**:

``` rust
   POST /auth/register
   {
     "email": "user@example.com",
     "password": "secure_password",
     "username": "username"
   }
```

1. **Login**:

``` rust
   POST /auth/login
   {
     "email": "user@example.com",
     "password": "secure_password"
   }
```

Response:

``` json
   {
  "status": 200,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "user_id",
      "email": "user@example.com",
      "username": "username",
      "roles": [
        "USER"
      ]
    },
    "tokens": {
      "access_token": "jwt_token_here",
      "refresh_token": "refresh_token_here",
      "access_expires_at": "2023-01-01T00:15:00Z",
      "refresh_expires_at": "2023-01-08T00:00:00Z"
    }
  }
}
```

1. **Token Refresh**:

``` rust
   POST /auth/refresh
   {
     "refresh_token": "refresh_token_here"
   }
```

1. **Protected Route Access**:

``` rust
   GET /api/protected-resource
   Authorization: Bearer jwt_token_here
```

### Middleware Implementation

The authentication middleware extracts and validates JWT tokens:

``` rust
pub async fn auth_middleware<B>(
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    State(state): State<Arc<AppState>>,
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError> {
    // Extract token from header
    let auth_header = auth_header.ok_or_else(|| AppError::authentication("Missing authentication token"))?;
    let token = auth_header.token();
    
    // Validate token and extract claims
    let claims = state.auth_service.validate_token(token)?;
    
    // Continue with the request, adding user claims to request extensions
    let mut request = request;
    request.extensions_mut().insert(UserClaims { 
        user_id: claims.sub,
        roles: claims.roles,
        // Other claims...
    });
    
    Ok(next.run(request).await)
}
```

## API Response Format

All API responses follow a consistent JSON structure:

``` json
{
  "status": 200,
  "message": "Operation successful",
  "data": {
    ...
  }
}
```

For errors:

``` json
{
  "status": 400,
  "message": "Invalid request: Username already taken",
  "code": "CONFLICT",
  "details": {
    ...
  }
}
```

## Error Handling Strategy

The error system converts application-specific errors into HTTP responses with appropriate status codes and detailed
messages. This ensures:

1. Consistent error formats across the API
2. Clear information for API consumers
3. Secure error handling that doesn't leak sensitive details
4. Easy debugging with detailed internal error information

## Usage Examples

### Registering a User

``` rust
// Handler
pub async fn register_user(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterUserDto>,
) -> Result<ApiResponse<UserResponseDto>, AppError> {
    let user = state.user_service.register_user(&payload).await?;
    Ok(ApiResponse::created(user.into()))
}

// Client request
POST /api/users/register
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword"
}
```

### Authenticating and Accessing Protected Resources

``` rust
// Login first to get tokens
POST /auth/login
{
  "email": "user@example.com",
  "password": "securepassword"
}

// Then use the access token for protected routes
GET /api/protected-resource
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Setting Up MFA

``` rust
// Start MFA setup
POST /auth/mfa/setup
Authorization: Bearer access_token

// Verify and enable MFA
POST /auth/mfa/verify
Authorization: Bearer access_token
{
  "code": "123456"
}
```

### Handling Errors

``` rust
// In your service layer
if user_exists {
    return Err(AppError::conflict("Username already taken"));
}

// Auto-converts to HTTP response with status 409 and JSON body
```

## Testing Approach

The system includes comprehensive tests for handlers and the error system:

- **Unit Tests**: Verify individual handler logic
- **Integration Tests**: Test the full request-response cycle
- **Mock Implementations**: Test service interactions in isolation

## Extendability

The system is designed to be extensible:

- Add new error types as needed
- Implement additional handlers for new functionality
- Extend the user model with custom fields
- Support additional authentication methods
- Add new MFA providers

**Créer une sécurité supplémentaire d'alerte agression dans le cas d'un home jacking ou kidnapping**

## License

This project is licensed under the MIT License. See the LICENSE file for details.