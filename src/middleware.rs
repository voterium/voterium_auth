use crate::models::{AppState, Claims};
use actix_web::{error, http::header, web};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use actix_web::{
    body::{BoxBody, EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    Error, HttpMessage,
};

const PUBLIC_PATHS: &'static [&str] = &[
    "/auth/login", 
    "/auth/register",
    "/auth/refresh",
];

pub async fn jwt_middleware<B>(
    app_state: web::Data<AppState>,
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B, BoxBody>>, Error>
where
    B: MessageBody + 'static,
{
    if PUBLIC_PATHS.contains(&req.path()) {
        // Proceed to the next middleware or handler
        let res = next.call(req).await?;
        return Ok(res.map_into_left_body());
    }

    match validate_jwt(&req, &app_state.decoding_key).await {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            let res = next.call(req).await?;
            Ok(res.map_into_left_body())
        }
        Err(_) => {
            let response = error::ErrorUnauthorized("Unauthorized").error_response();
            let res = req.into_response(response);
            Ok(res.map_into_right_body())
        }
    }
}

async fn validate_jwt(req: &ServiceRequest, decoding_key: &DecodingKey) -> Result<Claims, Error> {
    let auth_header = req.headers().get(header::AUTHORIZATION);
    let token = match auth_header {
        Some(header_value) => {
            let auth_str = header_value.to_str().unwrap_or("");
            if auth_str.starts_with("Bearer ") {
                Some(auth_str.trim_start_matches("Bearer ").to_string())
            } else {
                None
            }
        }
        None => None,
    };

    let token = match token {
        Some(t) => t,
        None => {
            return Err(error::ErrorUnauthorized(
                "Missing or invalid Authorization header",
            ))
        }
    };

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = true;

    // Decode and validate the JWT
    let token_data = decode::<Claims>(&token, &decoding_key, &validation)
        .map_err(|err| error::ErrorUnauthorized(format!("Invalid token: {}", err)))?;

    Ok(token_data.claims)
}
