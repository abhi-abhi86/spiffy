// Omega Kernel - Rust Crypto Accelerator
// High-performance cryptography for Bifrost P2P
// Callable from Python via PyO3

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};

/// AES-256-GCM encryption (faster than Python cryptography)
#[no_mangle]
pub extern "C" fn rust_encrypt_aes_gcm(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> i32 {
    unsafe {
        if key.is_null() || plaintext.is_null() || output.is_null() {
            return -1;
        }
        
        // Convert to slices
        let key_slice = std::slice::from_raw_parts(key, key_len);
        let plaintext_slice = std::slice::from_raw_parts(plaintext, plaintext_len);
        
        // Create cipher
        let cipher = match Aes256Gcm::new_from_slice(key_slice) {
            Ok(c) => c,
            Err(_) => return -2,
        };
        
        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt
        let ciphertext = match cipher.encrypt(&nonce, plaintext_slice) {
            Ok(ct) => ct,
            Err(_) => return -3,
        };
        
        // Combine nonce + ciphertext
        let total_len = 12 + ciphertext.len();
        if total_len > *output_len {
            return -4; // Buffer too small
        }
        
        let output_slice = std::slice::from_raw_parts_mut(output, total_len);
        output_slice[..12].copy_from_slice(&nonce);
        output_slice[12..].copy_from_slice(&ciphertext);
        
        *output_len = total_len;
        0 // Success
    }
}

/// AES-256-GCM decryption
#[no_mangle]
pub extern "C" fn rust_decrypt_aes_gcm(
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    output: *mut u8,
    output_len: *mut usize,
) -> i32 {
    unsafe {
        if key.is_null() || ciphertext.is_null() || output.is_null() {
            return -1;
        }
        
        if ciphertext_len < 12 {
            return -2; // Too short
        }
        
        let key_slice = std::slice::from_raw_parts(key, key_len);
        let ciphertext_slice = std::slice::from_raw_parts(ciphertext, ciphertext_len);
        
        // Create cipher
        let cipher = match Aes256Gcm::new_from_slice(key_slice) {
            Ok(c) => c,
            Err(_) => return -3,
        };
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext_slice[..12]);
        let ct = &ciphertext_slice[12..];
        
        // Decrypt
        let plaintext = match cipher.decrypt(nonce, ct) {
            Ok(pt) => pt,
            Err(_) => return -4, // Decryption failed (auth tag mismatch)
        };
        
        if plaintext.len() > *output_len {
            return -5; // Buffer too small
        }
        
        let output_slice = std::slice::from_raw_parts_mut(output, plaintext.len());
        output_slice.copy_from_slice(&plaintext);
        
        *output_len = plaintext.len();
        0 // Success
    }
}

/// SHA-256 hash (faster than Python hashlib)
#[no_mangle]
pub extern "C" fn rust_sha256(
    data: *const u8,
    data_len: usize,
    output: *mut u8,
) -> i32 {
    unsafe {
        if data.is_null() || output.is_null() {
            return -1;
        }
        
        let data_slice = std::slice::from_raw_parts(data, data_len);
        
        let mut hasher = Sha256::new();
        hasher.update(data_slice);
        let result = hasher.finalize();
        
        let output_slice = std::slice::from_raw_parts_mut(output, 32);
        output_slice.copy_from_slice(&result);
        
        0 // Success
    }
}

/// HMAC-SHA256 (for token validation)
#[no_mangle]
pub extern "C" fn rust_hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
) -> i32 {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    
    unsafe {
        if key.is_null() || data.is_null() || output.is_null() {
            return -1;
        }
        
        let key_slice = std::slice::from_raw_parts(key, key_len);
        let data_slice = std::slice::from_raw_parts(data, data_len);
        
        let mut mac: HmacSha256 = match Mac::new_from_slice(key_slice) {
            Ok(m) => m,
            Err(_) => return -2,
        };
        
        mac.update(data_slice);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        
        let output_slice = std::slice::from_raw_parts_mut(output, 32);
        output_slice.copy_from_slice(&code_bytes);
        
        0 // Success
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption() {
        let key = [0u8; 32];
        let plaintext = b"Hello, Omega!";
        let mut ciphertext = vec![0u8; 1024];
        let mut ct_len = ciphertext.len();
        
        let result = unsafe {
            rust_encrypt_aes_gcm(
                key.as_ptr(),
                key.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                ciphertext.as_mut_ptr(),
                &mut ct_len,
            )
        };
        
        assert_eq!(result, 0);
        assert!(ct_len > plaintext.len());
    }
}
