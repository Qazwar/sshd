/* project includes */
#include "CHmac.h"
#include "hmac_sha1.h"

namespace ssh
{
    /* CHmac::CreateInstance
     * Factory class for integrity algorithms.
     */
    CHmac * CHmac::CreateInstance( const std::string & name )
    {
        if( name == "hmac-sha1" )
            return new (std::nothrow) hmac_sha1();

        return NULL;
    }
};