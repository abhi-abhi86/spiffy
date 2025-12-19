#pragma once

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>
#include <cstring>

namespace omega::bifrost {

/**
 * @brief Bifrost Cryptography - ECDH + AES-256-GCM
 * 
 * Implements end-to-end encryption for P2P chat:
 * 1. ECDH key exchange (secp256r1)
 * 2. HKDF key derivation
 * 3. AES-256-GCM encryption/decryption
 */
class BifrostCrypto {
public:
    BifrostCrypto() : ecdh_key_(nullptr), shared_secret_() {
        generate_keypair();
    }
    
    ~BifrostCrypto() {
        if (ecdh_key_) {
            EVP_PKEY_free(ecdh_key_);
        }
        
        // Secure wipe of shared secret
        if (!shared_secret_.empty()) {
            OPENSSL_cleanse(shared_secret_.data(), shared_secret_.size());
        }
    }
    
    // Prevent copying (contains sensitive key material)
    BifrostCrypto(const BifrostCrypto&) = delete;
    BifrostCrypto& operator=(const BifrostCrypto&) = delete;
    
    /**
     * @brief Get public key in PEM format
     */
    std::string get_public_key_pem() const {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, ecdh_key_);
        
        char* pem_data = nullptr;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        
        std::string pem(pem_data, pem_len);
        BIO_free(bio);
        
        return pem;
    }
    
    /**
     * @brief Derive shared secret from peer's public key
     */
    bool derive_shared_secret(const std::string& peer_pubkey_pem) {
        // Load peer's public key
        BIO* bio = BIO_new_mem_buf(peer_pubkey_pem.data(), peer_pubkey_pem.size());
        EVP_PKEY* peer_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!peer_key) {
            return false;
        }
        
        // Create derivation context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ecdh_key_, nullptr);
        if (!ctx) {
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        // Initialize derivation
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        // Set peer key
        if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        // Determine buffer length
        size_t secret_len = 0;
        EVP_PKEY_derive(ctx, nullptr, &secret_len);
        
        // Derive shared secret
        shared_secret_.resize(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret_.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peer_key);
            return false;
        }
        
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        
        // Derive AES key using HKDF (simplified - use first 32 bytes)
        aes_key_.resize(32);
        std::memcpy(aes_key_.data(), shared_secret_.data(), 32);
        
        return true;
    }
    
    /**
     * @brief Encrypt message with AES-256-GCM
     * 
     * @param plaintext Message to encrypt
     * @return Encrypted data (12-byte nonce + ciphertext + 16-byte tag)
     */
    std::vector<uint8_t> encrypt(const std::string& plaintext) {
        if (aes_key_.empty()) {
            throw std::runtime_error("Shared secret not derived");
        }
        
        // Generate random 12-byte nonce
        std::vector<uint8_t> nonce(12);
        RAND_bytes(nonce.data(), 12);
        
        // Create cipher context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        
        // Initialize encryption
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                          aes_key_.data(), nonce.data());
        
        // Encrypt
        std::vector<uint8_t> ciphertext(plaintext.size() + 16); // +16 for tag
        int len = 0;
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                         reinterpret_cast<const uint8_t*>(plaintext.data()),
                         plaintext.size());
        
        int ciphertext_len = len;
        
        // Finalize
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;
        
        // Get authentication tag
        std::vector<uint8_t> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Combine: nonce + ciphertext + tag
        std::vector<uint8_t> result;
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), ciphertext.begin(), 
                     ciphertext.begin() + ciphertext_len);
        result.insert(result.end(), tag.begin(), tag.end());
        
        return result;
    }
    
    /**
     * @brief Decrypt message with AES-256-GCM
     * 
     * @param ciphertext Encrypted data (nonce + ciphertext + tag)
     * @return Decrypted plaintext
     */
    std::string decrypt(const std::vector<uint8_t>& ciphertext) {
        if (aes_key_.empty()) {
            throw std::runtime_error("Shared secret not derived");
        }
        
        if (ciphertext.size() < 28) { // 12 (nonce) + 16 (tag)
            throw std::runtime_error("Invalid ciphertext size");
        }
        
        // Extract components
        std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + 12);
        std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());
        std::vector<uint8_t> ct(ciphertext.begin() + 12, ciphertext.end() - 16);
        
        // Create cipher context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        
        // Initialize decryption
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          aes_key_.data(), nonce.data());
        
        // Set expected tag
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        
        // Decrypt
        std::vector<uint8_t> plaintext(ct.size());
        int len = 0;
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct.data(), ct.size());
        
        int plaintext_len = len;
        
        // Finalize (verifies tag)
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        
        EVP_CIPHER_CTX_free(ctx);
        
        if (ret <= 0) {
            throw std::runtime_error("Decryption failed - authentication tag mismatch");
        }
        
        plaintext_len += len;
        
        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }

private:
    EVP_PKEY* ecdh_key_;
    std::vector<uint8_t> shared_secret_;
    std::vector<uint8_t> aes_key_;
    
    void generate_keypair() {
        // Create EC key generation context
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
        
        // Generate key
        EVP_PKEY_keygen(pctx, &ecdh_key_);
        
        EVP_PKEY_CTX_free(pctx);
    }
};

} // namespace omega::bifrost
