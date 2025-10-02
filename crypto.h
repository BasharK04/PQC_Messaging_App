#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Simple AES-256-GCM helper.
 * - encrypt(): returns ciphertext || 16-byte tag
 * - decrypt(): expects ciphertext || 16-byte tag, throws if tag verify fails
 */
class AESGCMCrypto {
public:
    static constexpr size_t KEY_SIZE   = 32; // 256-bit
    static constexpr size_t NONCE_SIZE = 12; // 96-bit recommended for GCM
    static constexpr size_t TAG_SIZE   = 16; // 128-bit

    AESGCMCrypto() {
        // Hardcoded demo key (INSECURE: for demo only; replace with KEM-derived key later)
        key_ = {
            0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
            0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
        };
    }

    explicit AESGCMCrypto(const std::vector<uint8_t>& key) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("AESGCMCrypto: key must be 32 bytes");
        }
        key_ = key;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& nonce) const {
        if (nonce.size() != NONCE_SIZE) {
            throw std::invalid_argument("AESGCMCrypto::encrypt: nonce must be 12 bytes");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        std::vector<uint8_t> ciphertext(plaintext.size());
        std::vector<uint8_t> tag(TAG_SIZE);

        int len = 0;
        int outlen = 0;

        try {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                throw std::runtime_error("EncryptInit (cipher) failed");

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
                throw std::runtime_error("SET_IVLEN failed");

            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1)
                throw std::runtime_error("EncryptInit (key/iv) failed");

            // No AAD used

            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                  plaintext.data(), (int)plaintext.size()) != 1)
                throw std::runtime_error("EncryptUpdate failed");
            outlen = len;

            // GCM doesn't produce extra bytes here, but call anyway
            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &len) != 1)
                throw std::runtime_error("EncryptFinal failed");
            outlen += len;
            ciphertext.resize(outlen);

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag.data()) != 1)
                throw std::runtime_error("GET_TAG failed");

            EVP_CIPHER_CTX_free(ctx);
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }

        // append tag
        std::vector<uint8_t> out;
        out.reserve(ciphertext.size() + TAG_SIZE);
        out.insert(out.end(), ciphertext.begin(), ciphertext.end());
        out.insert(out.end(), tag.begin(), tag.end());
        return out;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext_and_tag,
                                 const std::vector<uint8_t>& nonce) const {
        if (nonce.size() != NONCE_SIZE) {
            throw std::invalid_argument("AESGCMCrypto::decrypt: nonce must be 12 bytes");
        }
        if (ciphertext_and_tag.size() < TAG_SIZE) {
            throw std::invalid_argument("AESGCMCrypto::decrypt: input too short");
        }

        const size_t ct_len = ciphertext_and_tag.size() - TAG_SIZE;
        const uint8_t* ct_ptr = ciphertext_and_tag.data();
        const uint8_t* tag_ptr = ciphertext_and_tag.data() + ct_len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

        std::vector<uint8_t> plaintext(ct_len);
        int len = 0;
        int outlen = 0;

        try {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
                throw std::runtime_error("DecryptInit (cipher) failed");

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce.size(), nullptr) != 1)
                throw std::runtime_error("SET_IVLEN failed");

            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1)
                throw std::runtime_error("DecryptInit (key/iv) failed");

            // No AAD used

            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ct_ptr, (int)ct_len) != 1)
                throw std::runtime_error("DecryptUpdate failed");
            outlen = len;

            // Provide expected tag
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void*)tag_ptr) != 1)
                throw std::runtime_error("SET_TAG failed");

            int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &len);
            if (ret <= 0) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error("GCM tag verification failed");
            }
            outlen += len;
            plaintext.resize(outlen);

            EVP_CIPHER_CTX_free(ctx);
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }

        return plaintext;
    }

    static std::vector<uint8_t> random_nonce() {
        std::vector<uint8_t> n(NONCE_SIZE);
        if (RAND_bytes(n.data(), (int)n.size()) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        return n;
    }

private:
    std::vector<uint8_t> key_;
};
