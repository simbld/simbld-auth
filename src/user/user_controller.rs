use crate::user::user_dto::{CreateUserRequest, UpdatePasswordRequest};
use crate::user::user_service::UserService;
use crate::utils::password_generator::generate_password;
use actix_web::{web, HttpResponse, Responder};
use deadpool_postgres::Pool;
use serde_json::json;
use simbld_http::responses::client::{bad_request, conflict};
use simbld_http::responses::local::{database_error, user_not_found};
use simbld_http::responses::server::internal_server_error;
use simbld_http::responses::success::{created, no_content, ok};

pub async fn all_users(pool: web::Data<Pool>) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return internal_server_error(),
  };

  match UserService::all_users(&client).await {
    Ok(users) => {
      let (code, description) = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&description).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({"users": users }));
      }
      HttpResponse::build(StatusCode::from_u16(code).unwrap()).json(base_json)
    },
    Err(_) => internal_server_error(),
  }
}

pub async fn create_user(
  body: web::Json<CreateUserRequest>,
  pool: web::Data<Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return internal_server_error(),
  };

  let password = if body.password.is_empty() {
    generate_password()
  } else {
    body.password.clone()
  };

  match UserService::add_user(&client, &body.username, &body.login, &body.email, Some(&password))
    .await
  {
    Ok(_) => {
      let (code, base_str) = created();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!(body));
      }
      HttpResponse::build(StatusCode::from_u16(code).unwrap()).json(base_json)
    },
    Err(conflict) => {
      let (code, base_str) = conflict();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!(already_exists));
      }
      HttpResponse::build(StatusCode::from_u16(code).unwrap()).json(base_json)
    },
    Err(bad_request) => {
      let (code, base_str) = bad_request();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!(invalid_password));
      }
      HttpResponse::build(StatusCode::from_u16(code).unwrap()).json(base_json)
    },
    Err(database_error(_)) => internal_server_error(),
    _ => internal_server_error(),
  }
}

pub async fn update_password(
  body: web::Json<UpdatePasswordRequest>,
  pool: web::Data<Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return internal_server_error(),
  };

  match UserService::update_password(&client, &body.email, &body.new_password).await {
    Ok(_) => {
      let base_str = ok();
      let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
      HttpResponse::ok().json(base_json)
    },
    Err(user_not_found) => {
      let base_str = user_not_found();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({"message": "User not found"}));
      }
      HttpResponse::NotFound().json(base_json)
    },
    Err(database_error(_)) => internal_server_error(),
    _ => internal_server_error(),
  }
}

pub async fn delete_user(req: web::Path<String>, pool: web::Data<Pool>) -> impl Responder {
  let login = req.into_inner();
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return internal_server_error(),
  };

  match UserService::delete_user(&client, &login).await {
    Ok(_) => {
      let base_str = no_content();
      let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
      HttpResponse::NoContent().json(base_json)
    },
    Err(user_not_found) => {
      let base_str = user_not_found();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({"message": "User not found"}));
      }
      HttpResponse::user_not_found().json(base_json)
    },
    Err(database_error(_)) => internal_server_error(),
    _ => internal_server_error(),
  }
}

pub async fn get_paginated_users(
  page: web::Query<u32>,
  page_size: web::Query<u32>,
  pool: web::Data<Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return internal_server_error(),
  };

  let page = *page;
  let page_size = *page_size;
  let offset = (page - 1) as i64 * page_size as i64;

  let total_users = match UserService::count_users(&client).await {
    Ok(count) => count,
    Err(database_error(_)) => return internal_server_error(),
    _ => return internal_server_error(),
  };

  let users =
    match UserService::get_users_with_pagination(&client, page_size as u64, offset as u64).await {
      Ok(u) => u,
      Err(database_error(_)) => return internal_server_error(),
      _ => return internal_server_error(),
    };

  let base_str = ok();
  let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
  if let Some(obj) = base_json.as_object_mut() {
    obj.insert(
      "data".to_string(),
      json!({
        "users": users,
        "total": total_users,
        "page": page,
        "page_size": page_size
      }),
    );
  }
  HttpResponse::ok().json(base_json)
}
