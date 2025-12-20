// Rust Chat Crypto - Backend (45% of work)
// Handles ALL cryptography for encrypted chat
// Python just calls these functions

use pyo3::prelude::*;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

/// Key pair for ECDH
#[pyclass]
pub struct KeyPair {
    #[pyo3(get)]
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[pymethods]
impl KeyPair {
    /// Get public key as bytes
    fn get_public(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Crypto engine - does ALL the heavy lifting
#[pyclass]
pub struct ChatCrypto {
    keypair: Option<KeyPair>,
    shared_secret: Option<Vec<u8>>,
}

#[pymethods]
impl ChatCrypto {
    #[new]
    fn new() -> Self {
        ChatCrypto {
            keypair: None,
            shared_secret: None,
        }
    }
    
    /// Generate ECDH keypair (X25519)
    /// Backend does: Generate random secret, compute public key
    fn generate_keypair(&mut self) -> PyResult<Vec<u8>> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        
        let public_bytes = public.as_bytes().to_vec();
        let secret_bytes = secret.to_bytes().to_vec();
        
        self.keypair = Some(KeyPair {
            public_key: public_bytes.clone(),
            secret_key: secret_bytes,
        });
        
        Ok(public_bytes)
    }
    
    /// Compute shared secret from peer's public key
    /// Backend does: ECDH computation, key derivation
    fn compute_shared_secret(&mut self, their_public: Vec<u8>) -> PyResult<bool> {
        if self.keypair.is_none() {
            return Ok(false);
        }
        
        let keypair = self.keypair.as_ref().unwrap();
        
        // Reconstruct our secret key
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&keypair.secret_key);
        let our_secret = EphemeralSecret::from(secret_bytes);
        
        // Parse their public key
        let mut their_public_bytes = [0u8; 32];
        if their_public.len() != 32 {
            return Ok(false);
        }
        their_public_bytes.copy_from_slice(&their_public);
        let their_public_key = PublicKey::from(their_public_bytes);
        
        // Compute shared secret
        let shared = our_secret.diffie_hellman(&their_public_key);
        
        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"encrypted-chat-key", &mut okm)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("HKDF failed"))?;
        
        self.shared_secret = Some(okm.to_vec());
        Ok(true)
    }
    
    /// Encrypt message with AES-256-GCM
    /// Backend does: Generate nonce, encrypt, return nonce+ciphertext
    fn encrypt(&self, message: Vec<u8>) -> PyResult<Vec<u8>> {
        if self.shared_secret.is_none() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "No shared secret. Call compute_shared_secret first"
            ));
        }
        
        let key_bytes = self.shared_secret.as_ref().unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        
        let cipher = Aes256Gcm::new(&key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher
            .encrypt(&nonce, message.as_ref())
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Encryption failed"))?;
        
        // Return: nonce (12 bytes) + ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt message with AES-256-GCM
    /// Backend does: Extract nonce, decrypt, verify auth tag
    fn decrypt(&self, encrypted: Vec<u8>) -> PyResult<Vec<u8>> {
        if self.shared_secret.is_none() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "No shared secret"
            ));
        }
        
        if encrypted.len() < 12 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Invalid encrypted data"
            ));
        }
        
        let key_bytes = self.shared_secret.as_ref().unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(key_bytes);
        
        let cipher = Aes256Gcm::new(&key.into());
        
        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Decryption failed (wrong key or tampered data)"
            ))?;
        
        Ok(plaintext)
    }
    
    /// Sign message with HMAC-SHA256
    /// Backend does: Compute HMAC over message
    fn sign(&self, message: Vec<u8>) -> PyResult<Vec<u8>> {
        if self.shared_secret.is_none() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "No shared secret"
            ));
        }
        
        let key = self.shared_secret.as_ref().unwrap();
        let mut mac: HmacSha256 = Mac::new_from_slice(key)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid key"))?;
        
        mac.update(&message);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }
    
    /// Verify message signature
    /// Backend does: Compute HMAC and compare
    fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        if self.shared_secret.is_none() {
            return Ok(false);
        }
        
        if signature.len() != 32 {
            return Ok(false);
        }
        
        let key = self.shared_secret.as_ref().unwrap();
        let mut mac: HmacSha256 = Mac::new_from_slice(key)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid key"))?;
        
        mac.update(&message);
        
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&signature);
        
        Ok(mac.verify_slice(&expected).is_ok())
    }
    
    /// Generate random bytes
    /// Backend does: Secure random generation
    #[staticmethod]
    fn random_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }
}

/// Python module
#[pymodule]
fn rust_chat_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ChatCrypto>()?;
    m.add_class::<KeyPair>()?;
    Ok(())
}
