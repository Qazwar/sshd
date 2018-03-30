/* CCipher.cpp
 *
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */


/* C/C++ includes */
#include "CCipher.h"
#include "aes.h"

namespace ssh
{
    /* CCipher::CreateInstance
     * Factory class for ciphers.
     */
    CCipher * CCipher::CreateInstance( const std::string & name )
    {
        /* Advanced Encryption Standard */
        if( name == "aes128-cbc" )
            return new (std::nothrow) aes( 16 ); /* 128 bits AES with CBC */
        else if( name == "aes256-cbc" )
            return new (std::nothrow) aes( 32 ); /* 256 bits AES with CRC */

        return NULL;
    }
};