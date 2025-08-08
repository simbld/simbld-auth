***Routes that REQUIRE authentication:***

- **GET /api/v1/protected** ← Basic user profile
- **GET /api/v1/protected/profile** ← Detailed profile
- **PUT /api/v1/protected/settings** ← Modify settings
- **GET /api/v1/protected/orders** ← View orders
- **POST /api/v1/protected/logout** ← Logout

***PUBLIC Routes:***

- **POST /api/v1/auth/register** ← Registration
- **POST /api/v1/auth/login** ← Login
- **GET /api/v1/health** ← API Status

---

- **Client Request**

- **↓**
-
- **[Header: Authorization: Bearer TOKEN]**

- **↓**
-
- **extract_auth_user()**

- **↓**
-
- **[Verify token with AuthService]**

- **↓**
-
- **✅ Valid token → AuthenticatedUser** = *protected_route()*
- **🛡️ Response with user data**


- **❌ Invalid token 401 Error** = *HttpResponse::Unauthorized*

# 1. Test basic health routes

curl http://localhost:3000/health
curl http://localhost:3000/health/detailed

# 2. Test auth (register)

curl -X POST http://localhost:3000/api/v1/auth/register \
-H "Content-Type: app/json" \
-d '{"email":"test@example.com","username":"testuser","password":"SecurePass123!"}'

# 3. Test auth (login)

curl -X POST http://localhost:3000/api/v1/auth/login \
-H "Content-Type: app/json" \
-d '{"email":"test@example.com","password":"SecurePass123!"}'

# 4. Test user management

curl http://localhost:3000/api/v1/users/550e8400-e29b-41d4-a716-446655440000