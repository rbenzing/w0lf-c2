#pragma once

#ifndef BASE64_H
#define BASE64_H

#include <string>

using namespace std;

namespace Base64 {

    /**
     * Encode a string into Base64 format.
     * @param data The input string to encode.
     * @return The Base64 encoded string.
     */
    string encode(const string& data);

    /**
     * Decode a Base64 encoded string into a regular string.
     * @param encoded_string The Base64 encoded string to decode.
     * @return The decoded string.
     */
    string decode(const string& encoded_string);

} // namespace Base64

#endif // BASE64_H
