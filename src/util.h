#ifndef _UTIL_H_
#define _UTIL_H_

#include <string>
#include <vector>

/*
 * STRING UTILITY
 */

/* SplitString
 * Splits the string using the delimitor and stores the strings in the vector.
 */
void SplitString(const std::string & str, std::vector<std::string> & vec, char delim);

/* Trim
 * Returns a trimmed version of the string
 */
std::string Trim(const std::string & str);

/* bin2hex
 *
 */
std::string bin2hex(const std::vector<uint8_t> & data);
#endif