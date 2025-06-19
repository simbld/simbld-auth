//! Authentication module for handling user authentication.
//!
//! This module contains all the functionality for user authentication,
//! including password management, multi-factor authentication,
//! session management, and token handling.

pub mod dto;
pub mod handlers;
pub mod jwt;
pub mod mfa;
pub mod middleware;
pub mod models;
pub mod oauth;
pub mod password;
pub mod service;
pub mod session;

use deadpool_postgres::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use self::mfa::{MfaError, MfaService, MfaStatus, MfaType};
use self::password::PasswordError;
use crate::users::User;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Password error: {0}")]
    PasswordError(#[from] PasswordError),

    #[error("MFA error: {0}")]
    MfaError(#[from] MfaError),

    #[error("User not found")]
    UserNotFound,

    #[error("User is locked")]
    UserLocked,

    #[error("Account is not verified")]
    AccountNotVerified,

    #[error("MFA required")]
    MfaRequired,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Session expired")]
    SessionExpired,
}

/// Successful authentication result
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub user_id: Uuid,
    pub requires_mfa: bool,
    pub mfa_methods: Vec<MfaType>,
    pub session_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

/// Authentication service handling login, MFA, and sessions
pub struct AuthService;

impl AuthService {
    /// Authenticate a user with username/email and password
    pub async fn authenticate(
        client: &Client,
        username_or_email: &str,
        password: &str,
    ) -> Result<AuthResult, AuthError> {
        // Récupérer l'utilisateur par nom d'utilisateur ou email
        let user = Self::get_user_by_identity(client, username_or_email).await?;

        // Vérifier si l'utilisateur est verrouillé ou désactivé
        if user.locked_until.is_some() || !user.active {
            return Err(AuthError::UserLocked);
        }

        // Vérifier si l'utilisateur a vérifié son compte (si requis)
        if !user.verified && crate::config::REQUIRE_EMAIL_VERIFICATION {
            return Err(AuthError::AccountNotVerified);
        }

        // Vérifier le mot de passe
        let verified = password::verify(password, &user.password_hash)
            .map_err(|e| AuthError::PasswordError(e))?;

        if !verified {
            // Gérer les tentatives de connexion échouées (à implémenter)
            Self::handle_failed_login_attempt(client, user.id).await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Réinitialiser les tentatives de connexion échouées
        Self::reset_failed_login_attempts(client, user.id).await?;

        // Vérifier si MFA est requis
        let mfa_status = MfaService::get_mfa_status(client, user.id)
            .await
            .map_err(|e| AuthError::MfaError(e))?;

        let requires_mfa = mfa_status.totp_enabled || mfa_status.webauthn_enabled;

        // Si MFA est activé, on ne génère pas encore de tokens
        if requires_mfa {
            let available_methods = Self::get_available_mfa_methods(&mfa_status);

            return Ok(AuthResult {
                user_id: user.id,
                requires_mfa: true,
                mfa_methods: available_methods,
                session_token: None,
                refresh_token: None,
                expires_at: None,
            });
        }

        // Si pas de MFA, générer des tokens d'authentification
        let (session_token, refresh_token, expires_at) =
            Self::generate_auth_tokens(client, user.id).await?;

        Ok(AuthResult {
            user_id: user.id,
            requires_mfa: false,
            mfa_methods: vec![],
            session_token: Some(session_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(expires_at),
        })
    }

    /// Vérifier l'authentification MFA
    pub async fn verify_mfa(
        client: &Client,
        user_id: Uuid,
        mfa_type: MfaType,
        code: &str,
    ) -> Result<AuthResult, AuthError> {
        // Vérifier le code MFA
        let verified = MfaService::verify_authentication(client, user_id, mfa_type, code)
            .await
            .map_err(|e| AuthError::MfaError(e))?;

        if !verified {
            return Err(AuthError::InvalidCredentials);
        }

        // Si MFA est vérifié, générer des tokens d'authentification
        let (session_token, refresh_token, expires_at) =
            Self::generate_auth_tokens(client, user_id).await?;

        Ok(AuthResult {
            user_id,
            requires_mfa: false,
            mfa_methods: vec![],
            session_token: Some(session_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(expires_at),
        })
    }

    /// Obtenir l'utilisateur par nom d'utilisateur ou email
    async fn get_user_by_identity(
        client: &Client,
        username_or_email: &str,
    ) -> Result<User, AuthError> {
        // Déterminer si l'entrée est un email ou un nom d'utilisateur
        let is_email = username_or_email.contains('@');

        let query = if is_email {
            "SELECT * FROM users WHERE email = $1"
        } else {
            "SELECT * FROM users WHERE username = $1"
        };

        let row = client
            .query_opt(query, &[&username_or_email])
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => Ok(User::from_row(row)),
            None => Err(AuthError::UserNotFound),
        }
    }

    /// Gérer une tentative de connexion échouée
    async fn handle_failed_login_attempt(client: &Client, user_id: Uuid) -> Result<(), AuthError> {
        // À implémenter: incrémenter le compteur de tentatives et verrouiller si nécessaire
        // Ceci est un emplacement pour une future implémentation
        Ok(())
    }

    /// Réinitialiser les tentatives de connexion échouées
    async fn reset_failed_login_attempts(client: &Client, user_id: Uuid) -> Result<(), AuthError> {
        // À implémenter: réinitialiser le compteur de tentatives
        // Ceci est un emplacement pour une future implémentation
        Ok(())
    }

    /// Obtenir les méthodes MFA disponibles basées sur le statut
    fn get_available_mfa_methods(mfa_status: &MfaStatus) -> Vec<MfaType> {
        let mut methods = Vec::new();

        if mfa_status.totp_enabled {
            methods.push(MfaType::Totp);
        }

        if mfa_status.webauthn_enabled {
            methods.push(MfaType::WebAuthn);
        }

        if mfa_status.backup_codes_available {
            methods.push(MfaType::BackupCode);
        }

        methods
    }

    /// Générer des tokens d'authentification
    async fn generate_auth_tokens(
        client: &Client,
        user_id: Uuid,
    ) -> Result<(String, String, i64), AuthError> {
        // Génération basique de tokens - à remplacer par JWT ou autre implémentation
        // Ceci est un emplacement pour une future implémentation
        let session_token = format!("session_{}", Uuid::new_v4());
        let refresh_token = format!("refresh_{}", Uuid::new_v4());
        let expires_at = chrono::Utc::now().timestamp() + 3600; // 1 heure

        Ok((session_token, refresh_token, expires_at))
    }
}
