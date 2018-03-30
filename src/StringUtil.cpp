/* StringUtil.cpp
 * Implements string utilities
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */
#include <string>
#include <vector>

using namespace std;

/* Trim
 * Returns a trimmed version of the string.
 */
string Trim(const string & str)
{
    string tmp;
    if( !str.empty() ) 
    {
        size_t first = str.find_first_not_of(' '), end = str.find_last_not_of(' ');
        if( first == string::npos || end == string::npos )
            return tmp;

        return str.substr(first, end-first+1);
    }
    return tmp;
}

/* SplitString
 * Splits the string using the delimitor and stores the result in the vector
 */
void SplitString(const string & str, vector<std::string> & vec, char delim)
{
    size_t pos;
    /* Trim the string */
    string tstr = Trim(str);

    do {
        /* find the position of the delimiter */
        pos = tstr.find_first_of(delim);
        if( pos != string::npos ) {
            vec.push_back(tstr.substr(0, pos)); /* add the substring to the vector */
            tstr = tstr.substr(pos+1);      
        }
    } while(pos != string::npos);
    /* add the rest of the string to the vector */
    vec.push_back(tstr);
}