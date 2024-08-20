#pragma once

#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/sha.h>

using namespace std;

namespace Crypto {

    string encryptData(const string& data, const string& sharedKey);
    string decryptData(const string& encrypted, const string& sharedKey);
    string sha256(const string& input);

} // namespace Crypto

#endif // CRYPTO_H
