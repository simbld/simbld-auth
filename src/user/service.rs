//! User Service Module
//!
//! This module provides the business logic for user management operations.
//! It serves as an intermediary layer between the API handlers and the data repository,
//! implementing validation, transformation, and business rules for user-related operations.

use crate::auth::password::PasswordHasher;
use crate::user::{
    error::UserError,
    model::{User, UserRole},
    repository::UserRepository,
};
use std::sync::Arc;
use uuid::Uuid;

/// Service for managing user-related operations
pub struct UserService {
    repo: Arc<dyn UserRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl UserService {
    /// Creates a new UserService with the given dependencies
    pub fn new(repo: Arc<dyn UserRepository>, password_hasher: Arc<dyn PasswordHasher>) -> Self {
        Self {
            repo,
            password_hasher,
        }
    }

    /// Registers a new local user with email and password
    pub async fn register_user(
        &self,
        username: String,
        email: String,
        password: String,
    ) -> Result<User, UserError> {
        // Validate input
        if username.trim().is_empty() {
            return Err(UserError::ValidationError("Username cannot be empty".to_string()));
        }

        if email.trim().is_empty() {
            return Err(UserError::ValidationError("Email cannot be empty".to_string()));
        }

        if !Self::is_valid_email(&email) {
            return Err(UserError::ValidationError("Invalid email format".to_string()));
        }

        if password.len() < 8 {
            return Err(UserError::ValidationError(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        // Check if email or username already exists
        if self.repo.find_by_email(&email).await?.is_some() {
            return Err(UserError::EmailAlreadyExists);
        }

        if self.repo.find_by_username(&username).await?.is_some() {
            return Err(UserError::UsernameAlreadyExists);
        }

        // Hash password
        let password_hash = self
            .password_hasher
            .hash_password(&password)
            .map_err(|e| UserError::PasswordHashingError(e.to_string()))?;

        // Create and store user
        let user = User::new_local(username, email, password_hash);
        self.repo.create(&user).await?;

        Ok(user)
    }

    /// Gets a user by their ID
    pub async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, UserError> {
        self.repo.find_by_id(id).await
    }

    /// Gets a user by their email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        self.repo.find_by_email(email).await
    }

    /// Gets a user by their username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        self.repo.find_by_username(username).await
    }

    /// Updates a user's profile information
    pub async fn update_profile(
        &self,
        user_id: &Uuid,
        display_name: Option<String>,
        profile_image: Option<String>,
    ) -> Result<User, UserError> {
        // Get the current user
        let mut user = match self.repo.find_by_id(user_id).await? {
            Some(user) => user,
            None => return Err(UserError::UserNotFound),
        };

        // Update fields
        if let Some(name) = display_name {
            user.display_name = Some(name);
        }

        if let Some(image) = profile_image {
            user.profile_image = Some(image);
        }

        // Save updated user
        self.repo.update(&user).await?;
        Ok(user)
    }

    /// Changes a user's password
    pub async fn change_password(
        &self,
        user_id: &Uuid,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), UserError> {
        // Get the current user
        let mut user = match self.repo.find_by_id(user_id).await? {
            Some(user) => user,
            None => return Err(UserError::UserNotFound),
        };

        // OAuth users cannot change password this way
        if user.is_oauth_user() {
            return Err(UserError::OperationNotAllowed(
                "OAuth users cannot change password this way".to_string(),
            ));
        }

        // Validate current password
        let is_valid = self
            .password_hasher
            .verify_password(current_password, &user.password_hash)
            .map_err(|e| UserError::PasswordVerificationError(e.to_string()))?;

        if !is_valid {
            return Err(UserError::InvalidCredentials);
        }

        // Validate new password
        if new_password.len() < 8 {
            return Err(UserError::ValidationError(
                "New password must be at least 8 characters long".to_string(),
            ));
        }

        // Hash and update password
        let password_hash = self
            .password_hasher
            .hash_password(new_password)
            .map_err(|e| UserError::PasswordHashingError(e.to_string()))?;

        user.password_hash = password_hash;
        self.repo.update(&user).await?;

        Ok(())
    }

    /// Creates or updates a user from OAuth provider data
    pub async fn create_or_update_oauth_user(
        &self,
        email: String,
        provider: String,
        provider_user_id: String,
        display_name: Option<String>,
        profile_image: Option<String>,
    ) -> Result<User, UserError> {
        // Check if user exists by provider info
        if let Some(mut existing_user) =
            self.repo.find_by_provider(&provider, &provider_user_id).await?
        {
            // Update user information
            if let Some(name) = display_name {
                existing_user.display_name = Some(name);
            }

            if let Some(image) = profile_image {
                existing_user.profile_image = Some(image);
            }

            self.repo.update(&existing_user).await?;
            return Ok(existing_user);
        }

        // Check if user exists by email
        if let Some(mut existing_user) = self.repo.find_by_email(&email).await? {
            // Link provider to existing user
            existing_user.provider = provider;
            existing_user.provider_user_id = provider_user_id;

            if let Some(name) = display_name {
                existing_user.display_name = Some(name);
            }

            if let Some(image) = profile_image {
                existing_user.profile_image = Some(image);
            }

            self.repo.update(&existing_user).await?;
            return Ok(existing_user);
        }

        // Create new user
        let user = User::new_oauth(email, provider, provider_user_id, display_name, profile_image);
        self.repo.create(&user).await?;

        Ok(user)
    }

    /// Deletes a user account
    pub async fn delete_user(&self, user_id: &Uuid) -> Result<(), UserError> {
        if self.repo.find_by_id(user_id).await?.is_none() {
            return Err(UserError::UserNotFound);
        }

        self.repo.delete(user_id).await?;
        Ok(())
    }

    /// Assigns a role to a user
    pub async fn assign_role(&self, user_id: &Uuid, role: UserRole) -> Result<(), UserError> {
        if self.repo.find_by_id(user_id).await?.is_none() {
            return Err(UserError::UserNotFound);
        }

        self.repo.assign_role(user_id, role).await?;
        Ok(())
    }

    /// Gets roles assigned to a user
    pub async fn get_user_roles(&self, user_id: &Uuid) -> Result<Vec<UserRole>, UserError> {
        if self.repo.find_by_id(user_id).await?.is_none() {
            return Err(UserError::UserNotFound);
        }

        self.repo.get_user_roles(user_id).await
    }

    /// Validates email format
    fn is_valid_email(email: &str) -> bool {
        // Basic email validation with regex
        let email_regex = regex::Regex::new(
            r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})",
        )
        .unwrap();

        email_regex.is_match(email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::password::TestPasswordHasher;
    use crate::mocks::mock_client::MockUserRepository;

    #[tokio::test]
    async fn test_register_user_success() {
        let repo = Arc::new(MockUserRepository::new());
        let password_hasher = Arc::new(TestPasswordHasher::new());
        let service = UserService::new(repo.clone(), password_hasher);

        let result = service
            .register_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "password123".to_string(),
            )
            .await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_register_user_invalid_email() {
        let repo = Arc::new(MockUserRepository::new());
        let password_hasher = Arc::new(TestPasswordHasher::new());
        let service = UserService::new(repo, password_hasher);

        let result = service
            .register_user(
                "testuser".to_string(),
                "invalid-email".to_string(),
                "password123".to_string(),
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(UserError::ValidationError(msg)) => {
                assert!(msg.contains("Invalid email"));
            },
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_register_user_short_password() {
        let repo = Arc::new(MockUserRepository::new());
        let password_hasher = Arc::new(TestPasswordHasher::new());
        let service = UserService::new(repo, password_hasher);

        let result = service
            .register_user(
                "testuser".to_string(),
                "test@example.com".to_string(),
                "short".to_string(),
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(UserError::ValidationError(msg)) => {
                assert!(msg.contains("Password must be at least 8 characters"));
            },
            _ => panic!("Expected ValidationError"),
        }
    }
}
