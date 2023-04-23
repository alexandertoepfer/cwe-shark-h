#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <cctype>
#include <map>
#include <list>
#include <algorithm>
#include <fstream>
#include <cmath>
#include <ios>
#include <vector>
#include <numeric>
/*
 * PLEASE BE AWARE THAT THE VULNERABILITY HAS BEEN IDENTIFIED AND SUCCESSFULLY CLOSED.
 * NO KNOWN ATTACKS HAVE BEEN EXECUTED USING THIS VULNERABILITY AND NO DATA WAS OBTAINABLE BY THIRD PARTIES.
 * THE INFORMATION PRESENTED IS FOR EDUCATIONAL PURPOSES ONLY AND DOES NOT REPRESENT AN ONGOING RISK.
 */

/*
 * Salt-Hash Approximation Recovery-attack with Known plaintext. Hashcat variant (SHARK-H)
 *
 *                   _ ___                /^^\ /^\  /^^\_
 *       _          _@)@) \            ,,/ '` ~ `'~~ ', `\.
 *     _/o\_ _ _ _/~`.`...'~\        ./~~..,'`','',.,' '  ~:
 *    / `,'.~,~.~  .   , . , ~|,   ,/ .,' , ,. .. ,,.   `,  ~\_
 *   ( ' _' _ '_` _  '  .    , `\_/ .' ..' '  `  `   `..  `,   \_
 *    ~V~ V~ V~ V~ ~\ `   ' .  '    , ' .,.,''`.,.''`.,.``. ',   \_
 *     _/\ /\ /\ /\_/, . ' ,   `_/~\_ .' .,. ,, , _/~\_ `. `. '.,  \_
 *    < ~ ~ '~`'~'`, .,  .   `_: ::: \_ '      `_/ ::: \_ `.,' . ',  \_
 *     \ ' `_  '`_    _    ',/ _::_::_ \ _    _/ _::_::_ \   `.,'.,`., \-,-,-,_,_,
 *      `'~~ `'~~ `'~~ `'~~  \(_)(_)(_)/  `~~' \(_)(_)(_)/ ~'`\_.._,._,'_;_;_;_;_;
 *
 * This is a demonstrative(1) recovery attack with which any low privilege user of the system
 * can potentially steal user credentials and perform actions using a different identity,
 * this works by exploiting the password reset feature shortly after a finished update cycle
 * in order for the attacker to map possible prng seeds to hash salts for hash predictions.
 *
 * (1): Assumptions regarding the customer environment were made upfront,
 *      which might not be accurately representative.
 * Author: Alexander Töpfer (https://github.com/alexandertoepfer)
 * Artwork by (https://www.asciiart.eu/)
 */

/*
 * MIT License
 *
 * Copyright (c) [2023] [Alexander, Toepfer (https://github.com/alexandertoepfer)]
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

#include "sha256.hpp"
/*
 * Implementation of the SHA-256 hashing algorithm.
 * Auther is Brad Conte (brad AT bradconte.com)
 * Algorithm specification can be found here:
 * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
 */
#include "md5.hpp"
/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */
#include "aes128.hpp"
/*
 * Implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
 * Block size can be chosen in aes128.hpp - available choices are AES128, AES192, AES256.
 * The implementation is verified against the test vectors in:
 * National Institute of Standards and Technology Special Publication 800-38A 2001 EDECB-AES128
 */
#include "utils.hpp"

int64_t x = 0;
int64_t random(void) {
  x = 25214903917 * x + 11;
  return (int64_t)((x >> 1) & ((uint64_t)(-1ull) >> 16));
}
int64_t random(int64_t seed) {
    return x = seed;
}

enum hashtype {
  MD5,
  SHA256
};


/*
 * Generic arithmetic hash class for calculations with hashes (hash + hash, hash - hash)
 * would have no use in cracking any other salting algorithm, when implemented using best practices.
 * https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/
 */
class am_hash {
public:
  std::string _hash = "";
  hashtype _type;
  am_hash() {}
  am_hash(const char* chr) {
    this->operator=(chr);
  }
  am_hash(am_hash&& move) : _hash(move._hash), _type(move._type) {}
  am_hash(const am_hash& move) : _hash(move._hash), _type(move._type) {}
  am_hash(hashtype type) : _type(type) {}
  am_hash& operator=(const char* hex) {
    std::string temp = hex;
    for(auto & c: temp)
      c = toupper(c);
    this->_hash = temp;
    return *this;
  }
  am_hash& operator=(const am_hash& other) {
    this->_hash = other._hash;
    this->_type = other._type;
    return *this;
  }
  am_hash& operator=(am_hash& other) {
    this->_hash = other._hash;
    this->_type = other._type;
    return *this;
  }
  am_hash& operator+(const std::string hex) {
  return this->operator+(hex.c_str());
  }
  am_hash& operator+(const std::string hex) const {
  return this->operator+(hex.c_str());
  }
  am_hash& operator+(const char* hex) {
    std::string str = hex;
    for(auto & c: str)
      c = toupper(c);
    if(!this->_hash.empty()) {
      this->_hash = add_hex(this->_hash, str);
    }
    return *this;
  }
  am_hash& operator-(const std::string hex) {
  return this->operator-(hex.c_str());
  }
  am_hash& operator-(const char* hex) {
    std::string str = hex;
    for(auto & c: str)
      c = toupper(c);
          if(!this->_hash.empty()) {
      this->_hash = sub_hex(this->_hash, str);
    }
    return *this;
  }
  const char* c_str() const {
    return this->_hash.c_str();
  }
  const std::string& str() const {
    return this->_hash;
  }
  const char* type() {
    return enum_str(this->_type);
  }
  bool empty() {
    return this->_hash.empty();
  }
  const char* enum_str(hashtype n) {
    switch(n) {
      case hashtype::MD5:     return "md5$";
      case hashtype::SHA256:  return "sha256$";
    }
    return "";
  }
  std::string add_hex(std::string a, std::string b) {
    std::map<char, int> m = hex_value_of_dec();
    std::map<int, char> k = dec_value_of_hex();

    if(a.length() < b.length())
      swap(a, b);

    int len1 = a.length(), len2 = b.length();
    std::string ans = "";
    int carry = 0, i, j;

    for(i = len1 - 1, j = len2 - 1;
        j >= 0; i--, j--) {
      int sum = m[a[i]] + m[b[j]] + carry;
      int addition_bit = k[sum % 16];
      ans.push_back(addition_bit);
      carry = sum / 16;
    }
    while(i >= 0) {
      int sum = m[a[i]] + carry;
      int addition_bit = k[sum % 16];
      ans.push_back(addition_bit);
      carry = sum / 16;
      i--;
    }
    if(carry) {
      ans.push_back(k[carry]);
    }
    std::reverse(ans.begin(), ans.end());
    return ans;
  }
  std::string sub_hex(std::string a, std::string b) {
    std::map<char, int> m = hex_value_of_dec();
    std::map<int, char> k = dec_value_of_hex();

    int len1 = a.length(), len2 = b.length();
    std::string ans = "";
    int carry = 0, y, z;

    for(y = len1 - 1, z = len2 - 1;
        z >= 0; y--, z--) {
       int sum = m[a[y]] - m[b[z]] - carry;
            if(sum < 0) {
                sum = m[a[y]] + 16 - m[b[z]] - carry;
                carry = 1;
            } else carry = 0;
      int addition_bit = k[sum % 16];
      ans.push_back(addition_bit);
    }
    while(y >= 0) {
      int sum = m[a[y]] - carry;
            if(sum < 0) {
                sum = m[a[y]] + 16 - carry;
                carry = 1;
            } else carry = 0;
      int addition_bit = k[sum % 16];
      ans.push_back(addition_bit);
      y--;
    }
    if(carry) {
      ans.push_back(k[carry]);
    }
    std::reverse(ans.begin(), ans.end());
    return ans;
  }
  std::map<char, int> hex_value_of_dec(void) {
    std::map<char, int> map {
      {'0', 0}, {'1', 1},
      {'2', 2}, {'3', 3},
      {'4', 4}, {'5', 5},
      {'6', 6}, {'7', 7},
      {'8', 8}, {'9', 9},
      {'A', 10}, {'B', 11},
      {'C', 12}, {'D', 13},
      {'E', 14}, {'F', 15}
    };
    return map;
  }
  std::map<int, char> dec_value_of_hex(void) {
    std::map<int, char> map {
      {0, '0'}, {1, '1'},
      {2, '2'}, {3, '3'},
      {4, '4'}, {5, '5'},
      {6, '6'}, {7, '7'},
      {8, '8'}, {9, '9'},
      {10, 'A'}, {11, 'B'},
      {12, 'C'}, {13, 'D'},
      {14, 'E'}, {15, 'F'}
    };
    return map;
  }
};

class aes128 {
public:
  aes128() {}
  std::string encrypt(std::string& text, std::string& key) {
    struct AES_ctx actx;
    pad(text, key);
    uint8_t iv[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t* k = (uint8_t*)key.c_str();
    uint8_t* t = (uint8_t*)text.c_str();
    AES_init_ctx_iv(&actx, k, iv);
    AES_CBC_encrypt_buffer(&actx, t, text.size());
    return string_to_hex(text);
  }
  std::string decrypt(std::string& text, std::string& key) {
    struct AES_ctx actx;
    pad(text, key);
    uint8_t iv[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    text = hex_to_string(text);
    uint8_t* k = (uint8_t*)key.c_str();
    uint8_t* c = (uint8_t*)text.c_str();
    AES_init_ctx_iv(&actx, k, iv);
    AES_CBC_decrypt_buffer(&actx, c, text.size());
    return text;
  }
  void pad(std::string& text, std::string& key) {
    for(int i = 0; text.size() % 16; i++) {
      text.append(std::string(1, (char)1));
    }
    for(int i = 0; key.size() % 16; i++) {
      key.append(std::string(1, (char)1));
    }
  }
};

int main() {
  aes128 aes128;

  random(16743294); //=> srand(16743298)
  random(); random();
  std::string key = "MyKey123";
  am_hash h1 = "8b2b65442026010e52863a402097d8cd" /*01test!*/, h2 = "946d20c91f154795805cebdefe919ef7" /*alex1*/, h3 = "53ebbc46d08e9224f6a45f8f2bf3d3ae" /*alex2*/,
          h4 = "7d8b3f275a4d647885edef96135c092d" /*020106009$*/, h5 = "979c369d0bd4f9651b3bb20833b9377d" /*3rd$hr3w!*/, h6 = "9110afd5827eab0d3b5af3788c152253" /*Fl0r1da$3*/, h7;
  for(am_hash& h : wrap(h1, h7, h2, h3, h7, h7, h4, h5, h7, h6)) {
      //std::cout << random() % ((uint64_t)(-1u) + 1) << std::endl;
    h = h + hexstr(random() % ((uint64_t)(-1u) + 1));
  }
  std::string json = "{\n\
    \"users\": {\n\
      \"administrator\"   :  \"" + h1.str() + "\",\n\
      \"alex-presenter\"  :  \"" + h2.str() + "\",\n\
      \"alex-operator\"   :  \"" + h3.str() + "\",\n\
      \"roger.dennis\"    :  \"" + h4.str() + "\",\n\
      \"johnny.peters\"   :  \"" + h5.str() + "\",\n\
      \"service\"         :  \"" + h6.str() + "\",\n\
  }\n}";
  std::cout << json << std::endl;
  std::cout << format(aes128.encrypt(json, key)) << std::endl << std::endl;

  return 0;
}
