use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
    errors::{ErrorKind, Result, new_error},
    signature::{Error as SignatureError, Signer, Verifier},
};
use p256::{
    ecdsa::{Signature, SigningKey, VerifyingKey, signature::Verifier as P256Verifier},
    pkcs8::DecodePrivateKey,
};

// jsonwebtoken's RustCrypto provider enables RSA even though the server only issues ES256 tokens.
// Keep jsonwebtoken for JWT/PEM handling and install a narrow ES256 provider locally.
static ES256_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory,
    verifier_factory,
    key_utils: KeyUtils::new_unimplemented(),
};

pub(crate) fn ensure_installed() {
    let _ = ES256_PROVIDER.install_default();
}

fn signer_factory(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>> {
    if *algorithm != Algorithm::ES256 {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    Ok(Box::new(Es256Signer::new(key)?))
}

fn verifier_factory(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>> {
    if *algorithm != Algorithm::ES256 {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }
    Ok(Box::new(Es256Verifier::new(key)?))
}

struct Es256Signer(SigningKey);

impl Es256Signer {
    fn new(key: &EncodingKey) -> Result<Self> {
        if key.family() != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        SigningKey::from_pkcs8_der(key.as_bytes())
            .map(Self)
            .map_err(|_| new_error(ErrorKind::InvalidEcdsaKey))
    }
}

impl Signer<Vec<u8>> for Es256Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, SignatureError> {
        let signature = self.0.sign_recoverable(msg).0;
        Ok(signature.to_vec())
    }
}

impl JwtSigner for Es256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

struct Es256Verifier(VerifyingKey);

impl Es256Verifier {
    fn new(key: &DecodingKey) -> Result<Self> {
        if key.family() != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }
        VerifyingKey::from_sec1_bytes(key.try_get_as_bytes()?)
            .map(Self)
            .map_err(|_| new_error(ErrorKind::InvalidEcdsaKey))
    }
}

impl Verifier<Vec<u8>> for Es256Verifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), SignatureError> {
        let signature = Signature::from_slice(signature).map_err(SignatureError::from_source)?;
        P256Verifier::verify(&self.0, msg, &signature).map_err(SignatureError::from_source)
    }
}

impl JwtVerifier for Es256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}
