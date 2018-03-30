/* CKeyExchange.cpp
 *
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "CKeyExchange.h"
#include "CDiffieHellman.h"
#include "DH_groups.h"
#include "CTransport.h"

namespace ssh
{
    /* CKeyExchange::CreateInstance
     * Creates a keyexchange instance based on the supplied name.
     */
    CKeyExchange * CKeyExchange::CreateInstance(const std::string & name, CTransport * ts)
    {
        if( name == "diffie-hellman-group1-sha1" ) 
        {
            return new (std::nothrow) CDiffieHellman( ts, DH_group1_safe_prime,DH_group1_generator );
        }
        else if( name == "diffie-hellman-group14-sha1" )
        {
            return new (std::nothrow) CDiffieHellman( ts, DH_group14_safe_prime,DH_group14_generator );
        }
        return NULL;
    }
};