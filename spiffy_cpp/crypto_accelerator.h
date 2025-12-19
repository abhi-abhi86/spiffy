#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace spiffy {

/**
 * Hardware-accelerated cryptography operations using OpenSSL
 */
class CryptoAccelerator {
public:
    CryptoAccelerator();
    ~CryptoAccelerator();

    /**
     * AES-256-GCM encryption
     * @param plaintext Data to encrypt
     * @param key 32-byte encryption key (hex string)
     * @return Base64-encoded ciphertext with nonce and tag
     */
    std::string aes_gcm_encrypt(const std::string& plaintext, const std::string& key);

    /**
     * AES-256-GCM decryption
     * @param ciphertext Base64-encoded data with nonce and tag
     * @param key 32-byte encryption key (hex string)
     * @return Decrypted plaintext
     */
    std::string aes_gcm_decrypt(const std::string& ciphertext, const std::string& key);

    /**
     * Generate secure random bytes
     * @param num_bytes Number of random bytes to generate
     * @return Hex-encoded random bytes
     */
    std::string generate_random(int num_bytes);

    /**
     * SHA-256 hash
     * @param data Data to hash
     * @return Hex-encoded hash
     */
    std::string sha256(const std::string& data);

    /**
     * PBKDF2 key derivation
     * @param password Password
     * @param salt Salt (hex string)
     * @param iterations Number of iterations
     * @param key_length Output key length in bytes
     * @return Derived key (hex string)
     */
    std::string pbkdf2(const std::string& password, const std::string& salt, 
                       int iterations, int key_length);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace spiffy
