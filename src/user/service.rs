//! User service layer
//!
//! Contains the business logic for user management operations.

use crate::user::{
    dto::*,
    error::UserError,
    models::{User, UserRole},
    repository::UserRepository,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

/// Service for managing user-related operations
pub struct UserService {
    repository: Arc<dyn UserRepository>,
}

impl UserService {
    /// Create a new UserService
    pub fn new(repository: Arc<dyn UserRepository>) -> Self {
        Self {
            repository,
        }
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
        self.repository.find_by_id(id).await
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        self.repository.find_by_email(email).await
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        self.repository.find_by_username(username).await
    }

    /// Update user profile
    pub async fn update_profile(
        &self,
        user_id: Uuid,
        request: UpdateProfileRequest,
    ) -> Result<(), UserError> {
        // Validation
        request.validate()?;

        // Check if a user exists
        if let Some(ref new_username) = request.username {
            if let Some(existing_user) = self.repository.find_by_username(new_username).await? {
                if existing_user.id != user_id {
                    return Err(UserError::UsernameTaken);
                }
            }
        }

        // Update the profile
        self.repository
            .update_profile(user_id, request.firstname, request.lastname, request.username)
            .await
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: Uuid,
        request: ChangePasswordRequest,
    ) -> Result<(), UserError> {
        // Validation
        request.validate()?;

        // TODO: Vérifier le mot de passe actuel
        // Pour l'instant, on met à jour directement
        self.repository.update_password(user_id, request.new_password).await
    }

    /// Update user status (Admin only)
    pub async fn update_user_status(
        &self,
        user_id: Uuid,
        request: UpdateUserStatusRequest,
    ) -> Result<(), UserError> {
        request.validate()?;
        self.repository.update_status(user_id, request.status).await
    }

    /// List users with pagination and filters
    pub async fn list_users(&self, query: ListUsersQuery) -> Result<UserListResponse, UserError> {
        // Validation et valeurs par défaut
        let limit = query.limit.unwrap_or(50);
        let offset = query.offset.unwrap_or(0);
        let status = query.status;
        let search = query.search.clone();

        // Valider les paramètres
        let validated_query = ListUsersQuery {
            limit: Some(limit),
            offset: Some(offset),
            status,
            search: search.clone(),
            ..query
        };
        validated_query.validate()?;

        // Récupérer les utilisateurs
        let users = self.repository.list_users(limit, offset, status, search.clone()).await?;

        // Compter le total
        let total = self.repository.count_users(status, search).await?;

        // Convertir en UserSummary et récupérer les rôles
        let mut user_summaries = Vec::new();
        for user in users {
            let roles = self.repository.get_user_roles(user.id).await.unwrap_or_default();

            let display_name = user.display_name();
            let user_id = user.id;
            let last_login = user.last_login;
            let created_at = user.created_at;

            let summary = UserSummary {
                id: user_id.to_string(),
                username: user.username,
                email: user.email,
                display_name,
                status: user.status,
                email_verified: user.email_verified,
                mfa_enabled: user.mfa_enabled,
                roles,
                last_login: datetime_to_string(last_login),
                created_at: datetime_to_string_required(created_at),
            };
            user_summaries.push(summary);
        }

        Ok(UserListResponse {
            users: user_summaries,
            total,
            limit,
            offset,
        })
    }

    /// Assign a role to a user (Admin only)
    pub async fn assign_role(
        &self,
        user_id: Uuid,
        request: AssignRoleRequest,
    ) -> Result<(), UserError> {
        request.validate()?;

        // Check if a user exists
        if self.repository.find_by_id(user_id).await?.is_none() {
            return Err(UserError::UserNotFound);
        }

        self.repository.assign_role(user_id, request.role).await
    }

    /// Get user roles
    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<UserRole>, UserError> {
        // Check if a user exists
        if self.repository.find_by_id(user_id).await?.is_none() {
            return Err(UserError::UserNotFound);
        }

        self.repository.get_user_roles(user_id).await
    }

    /// Get user statistics (Admin only)
    pub async fn get_user_stats(&self) -> Result<UserStatsResponse, UserError> {
        let stats = self.repository.get_user_stats().await?;

        Ok(UserStatsResponse {
            total_users: stats.total_users,
            active_users: stats.active_users,
            pending_users: stats.pending_users,
            suspended_users: stats.suspended_users,
            verified_emails: stats.verified_emails,
            mfa_enabled: stats.mfa_enabled,
            recent_logins: stats.recent_logins,
        })
    }

    /// Convert User to UserResponse
    pub fn user_to_response(&self, user: User) -> UserResponse {
        let display_name = user.display_name();
        let last_login = user.last_login;
        let created_at = user.created_at;
        let updated_at = user.updated_at;

        UserResponse {
            id: user.id.to_string(),
            username: user.username,
            email: user.email,
            firstname: user.firstname,
            lastname: user.lastname,
            display_name,
            email_verified: user.email_verified,
            mfa_enabled: user.mfa_enabled,
            status: user.status,
            last_login: datetime_to_string(last_login),
            created_at: datetime_to_string_required(created_at),
            updated_at: datetime_to_string_required(updated_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::models::UserStatus;
    use crate::user::repository::UserStatsData;
    use async_trait::async_trait;

    struct MockUserRepository {
        users: Vec<User>,
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
            Ok(self.users.iter().find(|u| u.id == id).cloned())
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
            Ok(self.users.iter().find(|u| u.email == email).cloned())
        }

        async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
            Ok(self.users.iter().find(|u| u.username == username).cloned())
        }

        async fn update_profile(
            &self,
            _user_id: Uuid,
            _firstname: Option<String>,
            _lastname: Option<String>,
            _username: Option<String>,
        ) -> Result<(), UserError> {
            Ok(())
        }

        async fn update_password(
            &self,
            _user_id: Uuid,
            _password: String,
        ) -> Result<(), UserError> {
            Ok(())
        }

        async fn update_status(
            &self,
            _user_id: Uuid,
            _status: UserStatus,
        ) -> Result<(), UserError> {
            Ok(())
        }

        async fn list_users(
            &self,
            _limit: i64,
            _offset: i64,
            _status: Option<UserStatus>,
            _search: Option<String>,
        ) -> Result<Vec<User>, UserError> {
            Ok(self.users.clone())
        }

        async fn count_users(
            &self,
            _status: Option<UserStatus>,
            _search: Option<String>,
        ) -> Result<i64, UserError> {
            Ok(self.users.len() as i64)
        }

        async fn assign_role(&self, _user_id: Uuid, _role: UserRole) -> Result<(), UserError> {
            Ok(())
        }

        async fn get_user_roles(&self, _user_id: Uuid) -> Result<Vec<UserRole>, UserError> {
            Ok(vec![UserRole::User])
        }

        async fn get_user_stats(&self) -> Result<UserStatsData, UserError> {
            Ok(UserStatsData {
                total_users: 1,
                active_users: 1,
                pending_users: 0,
                suspended_users: 0,
                verified_emails: 1,
                mfa_enabled: 0,
                recent_logins: 1,
            })
        }
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let mock_repo = Arc::new(MockUserRepository {
            users: vec![],
        });
        let service = UserService::new(mock_repo);

        let result = service.get_user_by_id(Uuid::new_v4()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_users() {
        let mock_repo = Arc::new(MockUserRepository {
            users: vec![],
        });
        let service = UserService::new(mock_repo);

        let query = ListUsersQuery::default();
        let result = service.list_users(query).await;
        assert!(result.is_ok());
    }
}
