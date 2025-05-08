use chrono::{Duration, Utc};
use thiserror::Error;
use uuid::Uuid;
use deadpool_postgres::Client;

use crate::auth::{
  jwt::JwtService,
  mfa::MfaService,
  models::{User, RefreshToken},
  password::PasswordService,
  repository::AuthRepository,
};

#[derive(Error, Debug)]
pub enum AuthError {
  #[error("User not found")]
  UserNotFound,
  #[error("Invalid credentials")]
  InvalidCredentials,
  #[error("Account locked")]
  AccountLocked,
  #[error("MFA required")]
  MfaRequired,
  #[error("Invalid MFA code")]
  InvalidMfaCode,
  #[error("Token expired")]
  TokenExpired,
  #[error("Invalid token")]
  InvalidToken,
  #[error("Database error: {0}")]
  DatabaseError(String),
  #[error("Hashing error: {0}")]
  HashingError(String),
  #[error("User already exists")]
  UserAlreadyExists,
  #[error("Internal server error: {0}")]
  InternalError(String),
}

#[derive(Debug)]
pub struct LoginResult {
  pub access_token: String,
  pub refresh_token: String,
  pub mfa_required: bool,
  pub user_id: Uuid,
  pub expires_in: i64,
}

pub struct AuthService {
  repository: AuthRepository,
  jwt_service: JwtService,
  mfa_service: MfaService,
  max_login_attempts: i32,
  refresh_token_expiration: Duration,
}

impl AuthService {
  pub fn new(
    repository: AuthRepository,
    jwt_service: JwtService,
    mfa_service: MfaService,
    max_login_attempts: i32,
    refresh_token_days: i64,
  ) -> Self {
    Self {
      repository,
      jwt_service,
      mfa_service,
      max_login_attempts,
      refresh_token_expiration: Duration::days(refresh_token_days),
    }
  }

  pub async fn register(
    &self,
    client: &Client,
    username: &str,
    email: &str,
    password: &str,
  ) -> Result<Uuid, AuthError> {
    // Vérifier si l'utilisateur existe déjà
    if self.repository.find_by_email(client, email).await.is_ok() {
      return Err(AuthError::UserAlreadyExists);
    }

    // Valider et hacher le mot de passe
    let password_hash = PasswordService::hash_password(password)
        .map_err(|e| AuthError::HashingError(e.to_string()))?;

    // Créer l'utilisateur
    let user_id = self.repository.create_user(
      client,
      username,
      email,
      &password_hash,
    )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // Attribuer le rôle d'utilisateur par défaut
    self.repository.assign_role(client, user_id, "user")
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    Ok(user_id)
  }

  pub async fn login(
    &self,
    client: &Client,
    email: &str,
    password: &str,
    ip_address: &str,
    user_agent: &str,
  ) -> Result<LoginResult, AuthError> {
    // Trouver l'utilisateur par email
    let user = self.repository.find_by_email(client, email)
        .await
        .map_err(|_| AuthError::UserNotFound)?;

    // Vérifier si le compte est verrouillé
    if user.account_locked {
      // Enregistrer la tentative de connexion échouée
      self.repository.record_login_attempt(
        client,
        Some(user.id),
        ip_address,
        user_agent,
        false
      )
          .await
          .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

      return Err(AuthError::AccountLocked);
    }

    // Vérifier le mot de passe
    let valid_password = PasswordService::verify_password(password, &user.password_hash)
        .map_err(|e| AuthError::HashingError(e.to_string()))?;

    if !valid_password {
      // Incrémenter le compteur de tentatives de connexion échouées
      let new_failed_attempts = user.failed_login_attempts + 1;
      let lock_account = new_failed_attempts >= self.max_login_attempts;

      self.repository.update_failed_login_attempts(
        client,
        user.id,
        new_failed_attempts,
        lock_account,
      )
          .await
          .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

      // Enregistrer la tentative de connexion échouée
      self.repository.record_login_attempt(
        client,
        Some(user.id),
        ip_address,
        user_agent,
        false
      )
          .await
          .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

      return Err(AuthError::InvalidCredentials);
    }

    // Mot de passe valide, vérifier si MFA est requis
    if user.mfa_enabled {
      // Enregistrer la tentative de connexion réussie mais nécessitant MFA
      self.repository.record_login_attempt(
        client,
        Some(user.id),
        ip_address,
        user_agent,
        true
      )
          .await
          .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

      return Ok(LoginResult {
        access_token: String::new(),
        refresh_token: String::new(),
        mfa_required: true,
        user_id: user.id,
        expires_in: 0,
      });
    }

    // Réinitialiser le compteur de tentatives de connexion échouées
    self.repository.update_failed_login_attempts(client, user.id, 0, false)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // Récupérer les rôles et permissions de l'utilisateur
    let roles = self.repository.get_user_roles(client, user.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let permissions = self.repository.get_user_permissions(client, user.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // Générer les tokens
    let access_token = self.jwt_service.generate_token(user.id, roles.clone(), permissions)
        .map_err(|e| AuthError::InternalError(e.to_string()))?;

    // Générer un refresh token
    let refresh_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + self.refresh_token_expiration;

    self.repository.create_refresh_token(client, user.id, &refresh_token, expires_at)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    // Mettre à jour la dernière connexion
    self.repository.update_last_login(client, user.id)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    // Enregistrer la tentative de connexion réussie
    self.repository.record_login_attempt(
      client,
      Some(user.id),
      ip_address,
      user_agent,
      true
    )
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    Ok(LoginResult {
      access_token,
      refresh_token,
      mfa_required: false,
      user_id: user.id,
      expires_in: self.jwt_service.token_expiration.num_seconds(),
    })
    }
    pub async fn verify_mfa(
        &self,
        client: &Client,
        user_id: Uuid,
        mfa_code: &str,
        ) -> Result<LoginResult, AuthError> {
        // Vérifier le code MFA
        let valid_mfa = self.mfa_service.verify_code(client, user_id, mfa_code)
            .await
            .map_err(|_| AuthError::InvalidMfaCode)?;

        if !valid_mfa {
            return Err(AuthError::InvalidMfaCode);
        }

        // Générer les tokens
        let access_token = self.jwt_service.generate_token(user_id, vec![], vec![])
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        // Générer un refresh token
        let refresh_token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + self.refresh_token_expiration;

        self.repository.create_refresh_token(client, user_id, &refresh_token, expires_at)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(LoginResult {
            access_token,
            refresh_token,
            mfa_required: false,
            user_id,
            expires_in: self.jwt_service.token_expiration.num_seconds(),
        })
        }
    pub async fn refresh_token(
        &self,
        client: &Client,
        user_id: Uuid,
        refresh_token: &str,
    ) -> Result<LoginResult, AuthError> {
        // Vérifier le refresh token
        let token = self.repository.find_refresh_token(client, user_id, refresh_token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        if token.expires_at < Utc::now() {
            return Err(AuthError::TokenExpired);
        }

        // Générer de nouveaux tokens
        let access_token = self.jwt_service.generate_token(user_id, vec![], vec![])
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        // Générer un nouveau refresh token
        let new_refresh_token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + self.refresh_token_expiration;

        self.repository.update_refresh_token(client, user_id, refresh_token, expires_at)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(LoginResult {
            access_token,
            refresh_token: new_refresh_token,
            mfa_required: false,
            user_id,
            expires_in: self.jwt_service.token_expiration.num_seconds(),
        })
    }
    pub async fn logout(
        &self,
        client: &Client,
        user_id: Uuid,
        refresh_token: &str,
    ) -> Result<(), AuthError> {
        self.repository.delete_refresh_token(client, user_id, refresh_token)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
    pub async fn get_user_info(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<User, AuthError> {
        self.repository.find_by_id(client, user_id)
            .await
            .map_err(|_| AuthError::UserNotFound)
    }
    pub async fn update_user(
        &self,
        client: &Client,
        user_id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        password: Option<&str>,
    ) -> Result<(), AuthError> {
        if let Some(password) = password {
            let password_hash = PasswordService::hash_password(password)
                .map_err(|e| AuthError::HashingError(e.to_string()))?;
            self.repository.update_password(client, user_id, &password_hash)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }

        self.repository.update_user(client, user_id, username, email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(())
    }
    pub async fn delete_user(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        self.repository.delete_user(client, user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
    pub async fn get_all_users(
        &self,
        client: &Client,
    ) -> Result<Vec<User>, AuthError> {
        self.repository.get_all_users(client)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_email(
        &self,
        client: &Client,
        email: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_email(client, email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_id(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_id(client, user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_username(
        &self,
        client: &Client,
        username: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_username(client, username)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_login(
        &self,
        client: &Client,
        login: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_login(client, login)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_refresh_token(
        &self,
        client: &Client,
        refresh_token: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_refresh_token(client, refresh_token)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_oauth(
        &self,
        client: &Client,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_oauth(client, provider, provider_user_id)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_oauth_token(
        &self,
        client: &Client,
        provider: &str,
        access_token: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_oauth_token(client, provider, access_token)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_oauth_refresh_token(
        &self,
        client: &Client,
        provider: &str,
        refresh_token: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_oauth_refresh_token(client, provider, refresh_token)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_oauth_expires_at(
        &self,
        client: &Client,
        provider: &str,
        expires_at: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_oauth_expires_at(client, provider, expires_at)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
    pub async fn get_user_by_oauth_access_token(
        &self,
        client: &Client,
        provider: &str,
        access_token: &str,
    ) -> Result<Option<User>, AuthError> {
        self.repository.find_by_oauth_access_token(client, provider, access_token)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))
    }
}
