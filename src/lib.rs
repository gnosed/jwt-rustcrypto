// #[cfg(target_arch = "wasm32")]
// extern crate wasm_bindgen;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_encode(header: &str, key: &str, payload: &str) -> Result<String, JsValue> {
    let header: Header =
        serde_json::from_str(header).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signing_key = SigningKey::from_secret(key.as_bytes());
    let payload: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| JsValue::from_str(&e.to_string()))?;
    encode(&header, &signing_key, &payload).map_err(|e| JsValue::from_str(&e.to_string()))
}

mod algorithm;
mod decode;
mod ecdsa_signing;
mod encode;
mod error;
mod header;
mod hmac_signing;
mod pem;
mod rsa_signing;
mod secret_key;
mod signing_key;
mod validation;
mod verifying_key;

pub use algorithm::Algorithm;
pub use decode::*;
pub(crate) use ecdsa_signing::*;
pub use encode::*;
pub use error::Error;
pub use header::Header;
pub(crate) use hmac_signing::*;
pub(crate) use pem::*;
use rsa_signing::*;
pub use secret_key::SecretKey;
pub use signing_key::*;
pub use validation::ValidationOptions;
pub use verifying_key::*;
