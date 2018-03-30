/* CHostKey.cpp
 * Implements a factory method for hostkey algorithms.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "CHostKey.h"
#include "rsa.h"

namespace ssh
{
    /* CHostKey::CreateInstance
     * Factory method for hostkey algorithms used for host verification.
     */
    CHostKey * CHostKey::CreateInstance(const std::string & name)
    {
        if( name == "ssh-rsa" ) 
        {
            /* RSA */
            return new (std::nothrow) ssh::rsa;
        } 
        return NULL;
    }
};