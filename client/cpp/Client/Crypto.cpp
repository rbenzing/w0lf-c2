#include "include\Crypto.h"
#include "include\Base64.h"

using namespace std;

namespace Crypto {

    string randomBytes(size_t length) {
        string result;
        result.resize(length);
        RAND_bytes(reinterpret_cast<unsigned char*>(&result[0]), static_cast<int>(length));
        return result;
    }

    string pbkdf2(const string& password, const string& salt, int iterations, int keyLength) {
        string result;
        result.resize(keyLength);
        PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
            reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
            iterations, EVP_sha512(), keyLength, reinterpret_cast<unsigned char*>(&result[0]));
        return result;
    }

    string encryptData(const string& data, const string& sharedKey) {
        string salt = randomBytes(32);
        string key = pbkdf2(sharedKey, salt, 200000, 32);
        string iv = randomBytes(16);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.c_str()),
            reinterpret_cast<const unsigned char*>(iv.c_str()));

        int len = 0;
        int ciphertext_len = 0;
        string ciphertext;

        ciphertext.resize(data.size() + EVP_CIPHER_CTX_block_size(ctx));
        EVP_EncryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
            reinterpret_cast<const unsigned char*>(data.c_str()), static_cast<int>(data.size()));
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(&ciphertext[ciphertext_len]), &len);
        ciphertext_len += len;

        string tag;
        tag.resize(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
            reinterpret_cast<unsigned char*>(&tag[0]));

        EVP_CIPHER_CTX_free(ctx);

        string result = salt + ":" + iv + ":" + tag + ":" + ciphertext.substr(0, ciphertext_len);
        return result;
    }

    string decryptData(const string& encrypted, const string& sharedKey) {
        size_t pos1 = encrypted.find(":");
        size_t pos2 = encrypted.find(":", pos1 + 1);
        size_t pos3 = encrypted.find(":", pos2 + 1);

        string salt_base64 = encrypted.substr(0, pos1);
        string iv_base64 = encrypted.substr(pos1 + 1, pos2 - pos1 - 1);
        string tag_base64 = encrypted.substr(pos2 + 1, pos3 - pos2 - 1);
        string encryptedData_base64 = encrypted.substr(pos3 + 1);

        string salt = Base64::decode(salt_base64);
        string iv = Base64::decode(iv_base64);
        string tag = Base64::decode(tag_base64);
        string encryptedData = Base64::decode(encryptedData_base64);

        string key = pbkdf2(sharedKey, salt, 200000, 32);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr,
            reinterpret_cast<const unsigned char*>(key.c_str()),
            reinterpret_cast<const unsigned char*>(iv.c_str()));

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
            reinterpret_cast<unsigned char*>(&tag[0]));

        int len = 0;
        int plaintext_len = 0;
        string plaintext;

        plaintext.resize(encryptedData.size() + EVP_CIPHER_CTX_block_size(ctx));
        EVP_DecryptUpdate(ctx,
            reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
            reinterpret_cast<const unsigned char*>(encryptedData.c_str()), static_cast<int>(encryptedData.size()));
        plaintext_len = len;

        EVP_DecryptFinal_ex(ctx,
            reinterpret_cast<unsigned char*>(&plaintext[plaintext_len]), &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }

    string sha256(const string& input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, input.c_str(), input.length());
        SHA256_Final(hash, &sha256);
        string output;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", hash[i]);
            output += hex;
        }
        return output;
    }

} // namespace Crypto
