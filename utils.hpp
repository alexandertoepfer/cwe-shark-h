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

int hex_value(unsigned char hex_digit) {
  static const signed char hex_values[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };
  int value = hex_values[hex_digit];
  if(value == -1)
    throw std::invalid_argument("invalid hex digit");
  return value;
}

std::string string_to_hex(const std::string& input) {
  static const char hex_digits[] = "0123456789ABCDEF";
  std::string output;
  output.reserve(input.length() * 2);
  for(unsigned char c : input) {
    output.push_back(hex_digits[c >> 4]);
    output.push_back(hex_digits[c & 15]);
  }
  return output;
}

std::string hex_to_string(const std::string& input) {
  const auto len = input.length();
  if(len & 1)
    throw std::invalid_argument("odd length");
  std::string output;
  output.reserve(len / 2);
  for(auto it = input.begin(); it != input.end()) {
    int high = hex_value(*it++);
    int low = hex_value(*it++);
    output.push_back(high << 4 | low);
  }
  return output;
}

std::string ul_to_hexs(unsigned long t) {
  std::ostringstream str;
  str << std::hex << t;
  return str.str();
}

unsigned long hexs_to_ul(std::string t) {
  std::stringstream str;
  unsigned long x;
  str << std::hex << t;
  str >> x;
  return x;
}

std::string format(std::string str) {
  std::stringstream convert;
  for(size_t i = 0; i < str.size(); i++) {
    if(!((i)%32))
      convert << '\n';
    convert << str[i];
  }
  return convert.str();
}

std::string unformat(std::string str) {
  str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
  return str;
}

size_t m_k = 0;
std::string nextqtd(std::string text) {
      size_t x = text.find('\"', m_k);
      size_t y = text.find('\"', x+1);
      m_k = y+1;
      return text.substr(x+1, y-x-1);
}
