use actix_web::{Error, HttpRequest, HttpResponse, Responder, error::ErrorServiceUnavailable, web};
use log::error;
use serde::{Deserialize, Serialize};
use crate::Pool;

#[derive(Deserialize)]
pub struct RegisterParams {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    id: i32,
    username: String,
}

impl Responder for RegisterResponse {
    type Error = Error;
    type Future = Result<HttpResponse, Error>;

    fn respond_to(self, _req: &HttpRequest) -> Self::Future {
        let body = serde_json::to_string(&self)?;

        Ok(HttpResponse::Created()
            .content_type("application/json")
            .body(body))
    }
}

// TODO: return meaningful result
pub fn register(params: web::Json<RegisterParams>, pool: web::Data<Pool>) -> Result<RegisterResponse, Error> {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return Err(ErrorServiceUnavailable(e));
        }
    };

    let crate::models::User { id, username, .. } = crate::create_user(
        &conn,
        params.username.as_str(),
        params.password.as_str(),
    );

    Ok(RegisterResponse { id, username })
}
