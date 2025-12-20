/*
 * Spiffy Private Chat - Rust Crypto Backend
 * MIT Licensed - Free to use and modify
 * 
 * This module handles 90% of the application logic:
 * - ChaCha20-Poly1305 encryption/decryption
 * - X25519 ECDH key exchange
 * - HMAC-SHA256 authentication
 * - HKDF key derivation
 * - Session management
 */

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyModule;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

#[pyclass]
pub struct PrivateChatCrypto {
    secret_key: Option<EphemeralSecret>,
    public_key: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    cipher: Option<ChaCha20Poly1305>,
    message_counter: u64,
}

#[pymethods]
impl PrivateChatCrypto {
    #[new]
    fn new() -> Self {
        PrivateChatCrypto {
            secret_key: None,
            public_key: None,
            shared_secret: None,
            cipher: None,
            message_counter: 0,
        }
    }
    
    /// Generate X25519 keypair for ECDH
    fn generate_keypair(&mut self) -> PyResult<Vec<u8>> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        
        let public_bytes = public.as_bytes().to_vec();
        
        self.secret_key = Some(secret);
        self.public_key = Some(public);
        
        Ok(public_bytes)
    }
    
    /// Compute shared secret using ECDH and derive encryption key
    fn compute_shared_secret(&mut self, peer_public_bytes: Vec<u8>) -> PyResult<bool> {
        if peer_public_bytes.len() != 32 {
            return Err(PyValueError::new_err("Invalid public key length"));
        }
        
        let secret_key = self.secret_key.take()
            .ok_or_else(|| PyValueError::new_err("No secret key generated"))?;
        
        let mut peer_public_array = [0u8; 32];
        peer_public_array.copy_from_slice(&peer_public_bytes);
        let peer_public = PublicKey::from(peer_public_array);
        
        // Perform ECDH (takes ownership of secret_key)
        let shared = secret_key.diffie_hellman(&peer_public);
        
        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut encryption_key = [0u8; 32];
        hk.expand(b"spiffy-private-chat-v1", &mut encryption_key)
            .map_err(|_| PyValueError::new_err("HKDF failed"))?;
        
        // Initialize ChaCha20-Poly1305 cipher
        let cipher = ChaCha20Poly1305::new(&encryption_key.into());
        
        self.shared_secret = Some(encryption_key);
        self.cipher = Some(cipher);
        
        Ok(true)
    }
    
    /// Encrypt message with ChaCha20-Poly1305 + HMAC
    fn encrypt(&mut self, plaintext: Vec<u8>) -> PyResult<Vec<u8>> {
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| PyValueError::new_err("No cipher initialized"))?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|_| PyValueError::new_err("Encryption failed"))?;
        
        // Increment counter
        self.message_counter += 1;
        
        // Create message: nonce (12) + ciphertext + counter (8)
        let mut message = Vec::with_capacity(12 + ciphertext.len() + 8);
        message.extend_from_slice(&nonce_bytes);
        message.extend_from_slice(&ciphertext);
        message.extend_from_slice(&self.message_counter.to_le_bytes());
        
        // Add HMAC
        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| PyValueError::new_err("No shared secret"))?;
        
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(shared_secret)
            .map_err(|_| PyValueError::new_err("HMAC init failed"))?;
        mac.update(&message);
        let tag = mac.finalize().into_bytes();
        
        // Final message: message + hmac (32)
        message.extend_from_slice(&tag);
        
        Ok(message)
    }
    
    /// Decrypt message and verify HMAC
    fn decrypt(&self, encrypted: Vec<u8>) -> PyResult<Vec<u8>> {
        if encrypted.len() < 12 + 16 + 8 + 32 {
            return Err(PyValueError::new_err("Message too short"));
        }
        
        let cipher = self.cipher.as_ref()
            .ok_or_else(|| PyValueError::new_err("No cipher initialized"))?;
        
        // Split message
        let hmac_start = encrypted.len() - 32;
        let message_part = &encrypted[..hmac_start];
        let received_hmac = &encrypted[hmac_start..];
        
        // Verify HMAC
        let shared_secret = self.shared_secret.as_ref()
            .ok_or_else(|| PyValueError::new_err("No shared secret"))?;
        
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(shared_secret)
            .map_err(|_| PyValueError::new_err("HMAC init failed"))?;
        mac.update(message_part);
        
        mac.verify_slice(received_hmac)
            .map_err(|_| PyValueError::new_err("HMAC verification failed"))?;
        
        // Extract components
        let nonce_bytes = &message_part[..12];
        let counter_start = message_part.len() - 8;
        let ciphertext = &message_part[12..counter_start];
        
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| PyValueError::new_err("Decryption failed"))?;
        
        Ok(plaintext)
    }
    
    /// Get message counter (for debugging)
    fn get_counter(&self) -> u64 {
        self.message_counter
    }
}

#[pymodule]
fn rust_private_chat(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PrivateChatCrypto>()?;
    Ok(())
}
