***Routes qui NÉCESSITENT une connexion :***

- **GET /api/v1/protected** ← Profil basique de l'utilisateur
- **GET /api/v1/protected/profile** ← Profil détaillé
- **PUT /api/v1/protected/settings** ← Modifier ses paramètres
- **GET /api/v1/protected/orders** ← Voir ses commandes
- **POST /api/v1/protected/logout** ← Se déconnecter

***Routes PUBLIQUES :***

- **POST /api/v1/auth/register** ← Inscription
- **POST /api/v1/auth/login** ← Connexion
- **GET /api/v1/health** ← Status de l'API

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
- **[Vérifie le token avec AuthService]**

- **↓**
-
- **✅ Token valide → AuthenticatedUser** = *protected_route()*
- **🛡️ Response avec données utilisateur**


- **❌ Token invalide 401 Error** = *HttpResponse::Unauthorized*

