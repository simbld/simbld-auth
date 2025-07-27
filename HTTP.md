## **📋 Case of uses of the AS_TUPLE function of the SIMBLD_HTTP API**

### **🔐 1. AUTHENTICATION**

- **JWT_EXPIRED** : Token JWT expiré
- **JWT_INVALID_SIGNATURE** : Signature JWT invalide
- **JWT_MALFORMED** : Token JWT malformé
- **JWT_MISSING_CLAIMS** : Claims manquants dans le JWT
- **JWT_BLACKLISTED** : Token dans la liste noire
- **JWT_REFRESH_REQUIRED** : Token principal expiré, refresh nécessaire
- **JWT_REFRESH_EXPIRED** : Token de refresh expiré
- **CREDENTIALS_INVALID** : Identifiants incorrects
- **ACCOUNT_LOCKED** : Compte verrouillé
- **ACCOUNT_SUSPENDED** : Compte suspendu
- **ACCOUNT_DISABLED** : Compte désactivé
- **LOGIN_ATTEMPTS_EXCEEDED** : Trop de tentatives de connexion

### **🔑 2. PASSWORD MANAGEMENT**

- **PASSWORD_TOO_SHORT** : Mot de passe trop court
- **PASSWORD_TOO_WEAK** : Mot de passe trop faible
- **PASSWORD_NO_UPPERCASE** : Pas de majuscules
- **PASSWORD_NO_LOWERCASE** : Pas de minuscules
- **PASSWORD_NO_DIGITS** : Pas de chiffres
- **PASSWORD_NO_SPECIAL_CHARS** : Pas de caractères spéciaux
- **PASSWORD_COMMON_WORD** : Mot de passe courant
- **PASSWORD_PERSONAL_INFO** : Contient des infos personnelles
- **PASSWORD_PREVIOUSLY_USED** : Mot de passe déjà utilisé
- **PASSWORD_COMPROMISED** : Mot de passe compromis (breach)
- **PASSWORD_RESET_TOKEN_EXPIRED** : Token de reset expiré
- **PASSWORD_RESET_TOKEN_INVALID** : Token de reset invalide
- **PASSWORD_RESET_LIMIT_EXCEEDED** : Trop de demandes de reset

### **🛡️ 3. MULTI-FACTOR AUTHENTICATION (MFA)**

- **MFA_REQUIRED** : MFA obligatoire
- **MFA_NOT_ENABLED** : MFA non activé
- **MFA_ALREADY_ENABLED** : MFA déjà activé
- **TOTP_INVALID** : Code TOTP invalide
- **TOTP_EXPIRED** : Code TOTP expiré
- **TOTP_ALREADY_USED** : Code TOTP déjà utilisé
- **BACKUP_CODE_INVALID** : Code de backup invalide
- **BACKUP_CODE_ALREADY_USED** : Code de backup déjà utilisé
- **BACKUP_CODES_EXHAUSTED** : Plus de codes de backup
- **WEBAUTHN_FAILED** : Authentification WebAuthn échouée
- **WEBAUTHN_NOT_SUPPORTED** : WebAuthn non supporté
- **SMS_FAILED** : Échec envoi SMS
- **SMS_RATE_LIMITED** : Trop de SMS envoyés
- **EMAIL_MFA_FAILED** : Échec MFA par email
- **PUSH_NOTIFICATION_FAILED** : Notification push échouée
- **DEVICE_NOT_TRUSTED** : Appareil non de confiance

### **📧 4. EMAIL MANAGEMENT**

- **EMAIL_ALREADY_EXISTS** : Email déjà utilisé
- **EMAIL_PENDING_VERIFICATION** : Email en attente de vérification
- **EMAIL_VERIFICATION_EXPIRED** : Vérification email expirée
- **EMAIL_VERIFICATION_FAILED** : Vérification email échouée
- **EMAIL_DOMAIN_BLOCKED** : Domaine email bloqué
- **EMAIL_INVALID_FORMAT** : Format email invalide
- **EMAIL_TEMPORARY_BLOCKED** : Email temporairement bloqué
- **EMAIL_DELIVERY_FAILED** : Échec livraison email

### **👤 5. USERS MANAGEMENT**

- **USER_NOT_FOUND** : Utilisateur introuvable
- **USER_ALREADY_EXISTS** : Utilisateur déjà existant
- **USER_INACTIVE** : Utilisateur inactif
- **USER_PROFILE_INCOMPLETE** : Profil utilisateur incomplet
- **USERNAME_TAKEN** : Nom d'utilisateur pris
- **USERNAME_INVALID** : Nom d'utilisateur invalide
- **USER_REGISTRATION_DISABLED** : Inscription désactivée
- **USER_DELETION_FAILED** : Suppression utilisateur échouée

### **🔒 6. AUTHORIZATION AND ROLES**

- **INSUFFICIENT_PERMISSIONS** : Permissions insuffisantes
- **ROLE_NOT_FOUND** : Rôle introuvable
- **ROLE_ASSIGNMENT_FAILED** : Échec assignation rôle
- **PERMISSION_DENIED** : Permission refusée
- **ADMIN_RIGHTS_REQUIRED** : Droits admin requis
- **ORGANIZATION_ACCESS_DENIED** : Accès organisation refusé
- **RESOURCE_ACCESS_DENIED** : Accès ressource refusé

### **📊 7. RATE LIMITING**

- : Limite de taux dépassée **RATE_LIMIT_EXCEEDED**
- **API_QUOTA_EXCEEDED** : Quota API dépassé
- **CONCURRENT_REQUESTS_LIMIT** : Limite requêtes simultanées
- **DAILY_LIMIT_EXCEEDED** : Limite quotidienne dépassée
- **HOURLY_LIMIT_EXCEEDED** : Limite horaire dépassée

### **🔐 8. SESSIONS AND TOKENS**

- **SESSION_EXPIRED** : Session expirée
- **SESSION_INVALID** : Session invalide
- **SESSION_LIMIT_EXCEEDED** : Limite de sessions dépassée
- **REFRESH_TOKEN_EXPIRED** : Token refresh expiré
- **REFRESH_TOKEN_INVALID** : Token refresh invalide
- **ACCESS_TOKEN_REQUIRED** : Token d'accès requis
- **TOKEN_GENERATION_FAILED** : Échec génération token

### **🌐 9. SAFETY AND GEOLOCATION**

- **SUSPICIOUS_ACTIVITY** : Activité suspecte
- **LOCATION_BLOCKED** : Localisation bloquée
- **IP_BLOCKED** : IP bloquée
- **DEVICE_FINGERPRINT_MISMATCH** : Empreinte appareil différente
- **UNUSUAL_LOGIN_PATTERN** : Pattern de connexion inhabituel
- **SECURITY_CHALLENGE_REQUIRED** : Challenge sécurité requis

### **🔗 10. EXTERNAL INTEGRATIONS**

- **OAUTH_PROVIDER_ERROR** : Erreur fournisseur OAuth
- **OAUTH_TOKEN_INVALID** : Token OAuth invalide
- **OAUTH_SCOPE_INSUFFICIENT** : Scope OAuth insuffisant
- **SOCIAL_LOGIN_FAILED** : Connexion sociale échouée
- **EXTERNAL_API_ERROR** : Erreur API externe
- **THIRD_PARTY_INTEGRATION_FAILED** : Intégration tierce échouée

### **💾 11. DATABASE AND STORAGE**

- **DATABASE_CONNECTION_FAILED** : Connexion DB échouée
- **DATABASE_QUERY_FAILED** : Requête DB échouée
- **DATABASE_CONSTRAINT_VIOLATION** : Violation contrainte DB
- **DATABASE_TIMEOUT** : Timeout DB
- **CACHE_MISS** : Cache manqué
- **CACHE_EXPIRED** : Cache expiré
- **STORAGE_QUOTA_EXCEEDED** : Quota stockage dépassé

### **⚙️ 12. VALIDATION AND CONFIGURATION**

- **VALIDATION_FAILED** : Validation échouée
- **REQUIRED_FIELD_MISSING** : Champ requis manquant
- **INVALID_INPUT_FORMAT** : Format d'entrée invalide
- **CONFIGURATION_ERROR** : Erreur de configuration
- **FEATURE_DISABLED** : Fonctionnalité désactivée
- **MAINTENANCE_MODE** : Mode maintenance
- **SERVICE_UNAVAILABLE** : Service indisponible
