use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use sha2::{Digest, Sha256};

use crate::{
    contracts::{DeviceChallenge, DeviceProof},
    error::{ApiError, Result},
};

const PROOF_DOMAIN: &[u8] = b"camellia.nexus.device-proof.v1";
const ACTIVATION_CODE_PREFIX: &str = "CNX1";
const ACTIVATION_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ACTIVATION_CODE_GROUPS: usize = 5;
const ACTIVATION_CODE_GROUP_LEN: usize = 5;

#[derive(Clone)]
pub struct EntitlementSigner {
    key_id: String,
    encoding_key: EncodingKey,
}

impl EntitlementSigner {
    pub fn from_pem(key_id: impl Into<String>, private_key_pem: &[u8]) -> Result<Self> {
        Ok(Self {
            key_id: key_id.into(),
            encoding_key: EncodingKey::from_ec_pem(private_key_pem)
                .map_err(|_| ApiError::SigningKeyUnavailable)?,
        })
    }

    #[cfg(test)]
    pub fn from_signing_key(key_id: impl Into<String>, key: &p256::ecdsa::SigningKey) -> Self {
        use p256::pkcs8::EncodePrivateKey;

        let pem = key.to_pkcs8_pem(Default::default()).expect("private pem");
        Self::from_pem(key_id, pem.as_bytes()).expect("signer")
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sign<T: serde::Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        crate::es256_provider::ensure_installed();
        encode(&header, claims, &self.encoding_key).map_err(|_| ApiError::SigningKeyUnavailable)
    }
}

pub fn verify_device_proof(
    public_key_pem: &str,
    challenge: &DeviceChallenge,
    proof: &DeviceProof,
    expected_device_id: &str,
    now: i64,
) -> Result<()> {
    if proof.challenge_id != challenge.challenge_id
        || proof.device_id != expected_device_id
        || proof.requested_scope != challenge.requested_scope
        || proof.issued_at != challenge.issued_at
        || challenge.expires_at <= now
    {
        return Err(ApiError::InvalidChallenge);
    }
    let verifying_key =
        VerifyingKey::from_public_key_pem(public_key_pem).map_err(|_| ApiError::InvalidRequest)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(ApiError::InvalidChallenge)?;
    verifying_key
        .verify(
            &proof_payload(
                &challenge.nonce,
                &proof.device_id,
                &proof.app_version,
                &proof.requested_scope,
                proof.issued_at,
            ),
            &signature,
        )
        .map_err(|_| ApiError::InvalidChallenge)
}

pub fn proof_payload(
    nonce: &str,
    device_id: &str,
    app_version: &str,
    requested_scope: &str,
    issued_at: i64,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(160);
    output.extend_from_slice(PROOF_DOMAIN);
    for value in [nonce, device_id, app_version, requested_scope] {
        let bytes = value.as_bytes();
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(bytes);
    }
    output.extend_from_slice(&issued_at.to_be_bytes());
    output
}

pub fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn generate_activation_code() -> String {
    let mut random = [0_u8; ACTIVATION_CODE_GROUPS * ACTIVATION_CODE_GROUP_LEN];
    rand::fill(&mut random);
    let mut output = String::with_capacity(
        ACTIVATION_CODE_PREFIX.len() + ACTIVATION_CODE_GROUPS * (ACTIVATION_CODE_GROUP_LEN + 1),
    );
    output.push_str(ACTIVATION_CODE_PREFIX);
    for group in random.chunks_exact(ACTIVATION_CODE_GROUP_LEN) {
        output.push('-');
        for byte in group {
            output.push(ACTIVATION_CODE_ALPHABET[(byte & 31) as usize] as char);
        }
    }
    output
}

pub fn canonicalize_activation_code(value: &str) -> Option<String> {
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    let payload = compact.strip_prefix(ACTIVATION_CODE_PREFIX)?;
    if payload.len() != ACTIVATION_CODE_GROUPS * ACTIVATION_CODE_GROUP_LEN {
        return None;
    }
    let normalized = payload
        .bytes()
        .map(|byte| match byte {
            b'O' => Some(b'0'),
            b'I' | b'L' => Some(b'1'),
            byte if ACTIVATION_CODE_ALPHABET.contains(&byte) => Some(byte),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let mut output = String::with_capacity(
        ACTIVATION_CODE_PREFIX.len() + ACTIVATION_CODE_GROUPS * (ACTIVATION_CODE_GROUP_LEN + 1),
    );
    output.push_str(ACTIVATION_CODE_PREFIX);
    for group in normalized.chunks_exact(ACTIVATION_CODE_GROUP_LEN) {
        output.push('-');
        output.extend(group.iter().map(|byte| *byte as char));
    }
    Some(output)
}

pub fn activation_code_prefix(code: &str) -> Option<String> {
    canonicalize_activation_code(code)
        .map(|canonical| canonical.split('-').take(3).collect::<Vec<_>>().join("-"))
}

pub fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    rand::fill(&mut bytes);
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}_{suffix}")
}

pub fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn stable_log_reference(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!("sha256:{}", sha256_hex(value))
    }
}

pub fn pkce_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
pub fn sign_device_challenge(
    key: &p256::ecdsa::SigningKey,
    challenge: &DeviceChallenge,
    device_id: &str,
    app_version: &str,
) -> DeviceProof {
    use p256::ecdsa::signature::Signer;

    let signature: Signature = key.sign(&proof_payload(
        &challenge.nonce,
        device_id,
        app_version,
        &challenge.requested_scope,
        challenge.issued_at,
    ));
    DeviceProof {
        challenge_id: challenge.challenge_id.clone(),
        device_id: device_id.to_owned(),
        app_version: app_version.to_owned(),
        requested_scope: challenge.requested_scope.clone(),
        issued_at: challenge.issued_at,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_activation_codes_are_canonical_and_high_entropy_length() {
        let first = generate_activation_code();
        let second = generate_activation_code();
        assert_ne!(first, second);
        assert_eq!(
            canonicalize_activation_code(&first).as_deref(),
            Some(first.as_str())
        );
        assert_eq!(
            first.split('-').map(str::len).collect::<Vec<_>>(),
            [4, 5, 5, 5, 5, 5]
        );
        assert_eq!(activation_code_prefix(&first).unwrap().len(), 16);
    }

    #[test]
    fn activation_code_input_is_case_hyphen_and_ambiguity_insensitive() {
        let canonical = "CNX1-01ABC-DEFGH-JKMNP-QRSTV-WXYZ2";
        assert_eq!(
            canonicalize_activation_code(" cnx1 oIabc defgh-jkmnp-qrstv-wxyz2 ").as_deref(),
            Some(canonical)
        );
        assert!(canonicalize_activation_code("CNX1-INVALID").is_none());
        assert!(canonicalize_activation_code("OTHER-01ABC-DEFGH-JKMNP-QRSTV-WXYZ2").is_none());
    }
}
