/* bin2hex
 * 
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

#include <string>
#include <vector>
#include "types.h"

using namespace std;

static const char table[] = {'0', '1', '2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

/* bin2hex
 * Converts binary data to the equivalent hexadecimal representation.
 */
string bin2hex(const std::vector<uint8_t> & data)
{
    string str;
    char c[3] = {0,0,0};
    for(size_t i = 0, count = data.size(); i < count; i++)
    {
        c[0] = table[data[i] >> 4];
        c[1] = table[data[i] & 0xff];
        str += c;
    }
    return str;
}

