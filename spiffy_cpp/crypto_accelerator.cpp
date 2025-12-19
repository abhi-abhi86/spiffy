#include "crypto_accelerator.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace spiffy {

// Helper functions for encoding/decoding
static std::string hex_encode(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

static std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static std::string base64_encode(const uint8_t* data, size_t len) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    
    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);
    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);
    return result;
}

static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    std::vector<uint8_t> result(encoded.length());
    int decoded_len = BIO_read(bio, result.data(), encoded.length());
    BIO_free_all(bio);
    
    result.resize(decoded_len);
    return result;
}

class CryptoAccelerator::Impl {
public:
    Impl() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~Impl() {
        EVP_cleanup();
        ERR_free_strings();
    }

    std::string aes_gcm_encrypt(const std::string& plaintext, const std::string& key_hex) {
        auto key_bytes = hex_decode(key_hex);
        if (key_bytes.size() != 32) {
            throw std::runtime_error("Key must be 32 bytes (64 hex chars)");
        }

        // Generate random nonce (12 bytes for GCM)
        uint8_t nonce[12];
        RAND_bytes(nonce, 12);

        // Prepare output buffer
        std::vector<uint8_t> ciphertext(plaintext.length() + 16); // +16 for tag
        uint8_t tag[16];

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_bytes.data(), nonce) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption init failed");
        }

        int len;
        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                             reinterpret_cast<const uint8_t*>(plaintext.data()), 
                             plaintext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed");
        }
        int ciphertext_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption finalization failed");
        }
        ciphertext_len += len;

        // Get tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get tag");
        }

        EVP_CIPHER_CTX_free(ctx);

        // Combine nonce + tag + ciphertext
        std::vector<uint8_t> result;
        result.insert(result.end(), nonce, nonce + 12);
        result.insert(result.end(), tag, tag + 16);
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        return base64_encode(result.data(), result.size());
    }

    std::string aes_gcm_decrypt(const std::string& ciphertext_b64, const std::string& key_hex) {
        auto key_bytes = hex_decode(key_hex);
        if (key_bytes.size() != 32) {
            throw std::runtime_error("Key must be 32 bytes (64 hex chars)");
        }

        auto data = base64_decode(ciphertext_b64);
        if (data.size() < 28) { // 12 (nonce) + 16 (tag)
            throw std::runtime_error("Invalid ciphertext");
        }

        // Extract nonce, tag, and ciphertext
        const uint8_t* nonce = data.data();
        const uint8_t* tag = data.data() + 12;
        const uint8_t* ciphertext = data.data() + 28;
        size_t ciphertext_len = data.size() - 28;

        std::vector<uint8_t> plaintext(ciphertext_len);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key_bytes.data(), nonce) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption init failed");
        }

        int len;
        // Decrypt ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed");
        }
        int plaintext_len = len;

        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set tag");
        }

        // Finalize decryption (verifies tag)
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed - authentication tag mismatch");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
    }

    std::string generate_random(int num_bytes) {
        std::vector<uint8_t> random_bytes(num_bytes);
        RAND_bytes(random_bytes.data(), num_bytes);
        return hex_encode(random_bytes.data(), num_bytes);
    }

    std::string sha256(const std::string& data) {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.length(), hash);
        return hex_encode(hash, SHA256_DIGEST_LENGTH);
    }

    std::string pbkdf2(const std::string& password, const std::string& salt_hex,
                       int iterations, int key_length) {
        auto salt = hex_decode(salt_hex);
        std::vector<uint8_t> key(key_length);

        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                              salt.data(), salt.size(),
                              iterations, EVP_sha256(),
                              key_length, key.data()) != 1) {
            throw std::runtime_error("PBKDF2 derivation failed");
        }

        return hex_encode(key.data(), key_length);
    }
};

// Public interface
CryptoAccelerator::CryptoAccelerator() : pImpl(std::make_unique<Impl>()) {}
CryptoAccelerator::~CryptoAccelerator() = default;

std::string CryptoAccelerator::aes_gcm_encrypt(const std::string& plaintext, const std::string& key) {
    return pImpl->aes_gcm_encrypt(plaintext, key);
}

std::string CryptoAccelerator::aes_gcm_decrypt(const std::string& ciphertext, const std::string& key) {
    return pImpl->aes_gcm_decrypt(ciphertext, key);
}

std::string CryptoAccelerator::generate_random(int num_bytes) {
    return pImpl->generate_random(num_bytes);
}

std::string CryptoAccelerator::sha256(const std::string& data) {
    return pImpl->sha256(data);
}

std::string CryptoAccelerator::pbkdf2(const std::string& password, const std::string& salt,
                                      int iterations, int key_length) {
    return pImpl->pbkdf2(password, salt, iterations, key_length);
}

} // namespace spiffy
