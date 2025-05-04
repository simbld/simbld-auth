use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

use crate::{
    auth::{
        jwt::JwtService,
        mfa::MfaService,
        service::AuthService,
    },
    utils::database::get_client_from_pool,
};
use crate::utils::password::security::PasswordService;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: String,

    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub user_id: Uuid,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupMfaRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyMfaSetupRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub secret: String,
    pub provisioning_uri: String,
}

pub async fn register(
    req: web::Json<RegisterRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    // Valider la requête
    if let Err(errors) = req.validate() {
        return HttpResponse::BadRequest().json(errors);
    }

    // Vérifier la force du mot de passe
    if let Err(err) = PasswordService::validate_password_strength(&req.password, &[&req.username, &req.email]) {
        return HttpResponse::BadRequest().json(err.to_string());
    }

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Créer l'utilisateur
    match auth_service.register(&client, &req.username, &req.email, &req.password).await {
        Ok(user_id) => HttpResponse::Created().json(user_id.to_string()),
        Err(err) => {
            match err {
                AuthError::UserAlreadyExists => HttpResponse::Conflict().json("User already exists"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn login(
    req: web::Json<LoginRequest>,
    http_req: HttpRequest,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    // Obtenir l'adresse IP et l'agent utilisateur
    let ip_address = http_req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let user_agent = http_req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Tentative de connexion
    match auth_service.login(&client, &req.email, &req.password, &ip_address, &user_agent).await {
        Ok(result) => {
            if result.mfa_required {
                HttpResponse::Ok().json(MfaRequiredResponse {
                    mfa_required: true,
                    user_id: result.user_id,
                })
            } else {
                HttpResponse::Ok().json(TokenResponse {
                    access_token: result.access_token,
                    refresh_token: result.refresh_token,
                    token_type: "Bearer".to_string(),
                    expires_in: result.expires_in,
                })
            }
        },
        Err(err) => {
            match err {
                AuthError::UserNotFound | AuthError::InvalidCredentials => {
                    HttpResponse::Unauthorized().json("Invalid credentials")
                },
                AuthError::AccountLocked => {
                    HttpResponse::Forbidden().json("Account locked. Please contact support.")
                },
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn verify_mfa(
    req: web::Json<MfaVerifyRequest>,
    http_req: HttpRequest,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    // Obtenir l'adresse IP et l'agent utilisateur
    let ip_address = http_req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let user_agent = http_req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Vérifier le code MFA
    match auth_service.verify_mfa(&client, req.user_id, &req.code, &ip_address, &user_agent).await {
        Ok(result) => {
            HttpResponse::Ok().json(TokenResponse {
                access_token: result.access_token,
                refresh_token: result.refresh_token,
                token_type: "Bearer".to_string(),
                expires_in: result.expires_in,
            })
        },
        Err(err) => {
            match err {
                AuthError::InvalidMfaCode => HttpResponse::Unauthorized().json("Invalid MFA code"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn refresh_token(
    req: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Rafraîchir le token
    match auth_service.refresh_token(&client, &req.refresh_token).await {
        Ok(result) => {
            HttpResponse::Ok().json(TokenResponse {
                access_token: result.access_token,
                refresh_token: result.refresh_token,
                token_type: "Bearer".to_string(),
                expires_in: result.expires_in,
            })
        },
        Err(err) => {
            match err {
                AuthError::InvalidToken => HttpResponse::Unauthorized().json("Invalid refresh token"),
                AuthError::TokenExpired => HttpResponse::Unauthorized().json("Refresh token expired"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn logout(
    req: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Déconnecter l'utilisateur
    match auth_service.logout(&client, &req.refresh_token).await {
        Ok(_) => HttpResponse::Ok().json("Successfully logged out"),
        Err(_) => HttpResponse::Ok().json("Successfully logged out"), // Même si le token est invalide, on considère l'utilisateur déconnecté
    }
}

pub async fn setup_mfa(
    req: web::Json<SetupMfaRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| HttpResponse::BadRequest().json("Invalid user ID"))?;

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Configurer MFA
    match auth_service.setup_mfa(&client, user_id, &req.password).await {
        Ok((secret, uri)) => {
            HttpResponse::Ok().json(MfaSetupResponse {
                secret,
                provisioning_uri: uri,
            })
        },
        Err(err) => {
            match err {
                AuthError::InvalidCredentials => HttpResponse::Unauthorized().json("Invalid password"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn verify_mfa_setup(
    req: web::Json<VerifyMfaSetupRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| HttpResponse::BadRequest().json("Invalid user ID"))?;

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Vérifier et activer MFA
    match auth_service.verify_mfa_setup(&client, user_id, &req.code).await {
        Ok(_) => HttpResponse::Ok().json("MFA successfully enabled"),
        Err(err) => {
            match err {
                AuthError::InvalidMfaCode => HttpResponse::BadRequest().json("Invalid MFA code"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn disable_mfa(
    req: web::Json<SetupMfaRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| HttpResponse::BadRequest().json("Invalid user ID"))?;

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Désactiver MFA
    match auth_service.disable_mfa(&client, user_id, &req.password).await {
        Ok(_) => HttpResponse::Ok().json("MFA successfully disabled"),
        Err(err) => {
            match err {
                AuthError::InvalidCredentials => HttpResponse::Unauthorized().json("Invalid password"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn change_password(
    req: web::Json<ChangePasswordRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| HttpResponse::BadRequest().json("Invalid user ID"))?;

    // Vérifier la force du nouveau mot de passe
    if let Err(err) = PasswordService::validate_password_strength(&req.new_password, &[]) {
        return HttpResponse::BadRequest().json(err.to_string());
    }

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Changer le mot de passe
    match auth_service.change_password(&client, user_id, &req.current_password, &req.new_password).await {
        Ok(_) => HttpResponse::Ok().json("Password successfully changed"),
        Err(err) => {
            match err {
                AuthError::InvalidCredentials => HttpResponse::Unauthorized().json("Current password is incorrect"),
                _ => HttpResponse::InternalServerError().json(err.to_string()),
            }
        }
    }
}

pub async fn get_me(
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| HttpResponse::BadRequest().json("Invalid user ID"))?;

    // Obtenir une connexion à la base de données
    let client = match get_client_from_pool(&db_pool).await {
        Ok(client) => client,
        Err(err) => return HttpResponse::InternalServerError().json(err.to_string()),
    };

    // Récupérer les informations de l'utilisateur
    match auth_service.get_user_profile(&client, user_id).await {
        Ok(profile) => HttpResponse::Ok().json(profile),
        Err(_) => HttpResponse::NotFound().json("User not found"),
    }
}
