use crate::{Algorithm, Error, SigningKey};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub(crate) fn sign_hmac(
    data: &str,
    signing_key: &SigningKey,
    alg: &Algorithm,
) -> Result<String, Error> {
    let key = match signing_key {
        SigningKey::Secret(secret) => secret.inner(),
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    let signature: Vec<u8> = match alg {
        Algorithm::HS256 => {
            let mut hmac = HmacSha256::new_from_slice(key)?;
            hmac.update(data.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS384 => {
            let mut hmac = HmacSha384::new_from_slice(key)?;
            hmac.update(data.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS512 => {
            let mut hmac = HmacSha512::new_from_slice(key)?;
            hmac.update(data.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature))
}
