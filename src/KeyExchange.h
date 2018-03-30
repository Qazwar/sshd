#ifndef _KEYEXCHANGE_H_
#define _KEYEXCHANGE_H_

/* C/C++ includes */
#include <string>

/* project includes */
#include "types.h"

enum 
{
    KEYEXCHANGE_METHOD = 0,
    SERVER_HOSTKEY,
    ENCRYPTION_CLIENT_TO_SERVER,
    ENCRYPTION_SERVER_TO_CLIENT,
    MAC_CLIENT_TO_SERVER,
    MAC_SERVER_TO_CLIENT,
    COMPRESSION_CLIENT_TO_SERVER,
    COMPRESSION_SERVER_TO_CLIENT,
    LANGUAGES_CLIENT_TO_SERVER,
    LANGUAGES_SERVER_TO_CLIENT,
    MAX_ALGORITHM_COUNT
};

namespace ssh
{
    /* KeyExchangeInfo
     * Contains the information for the SSH_MSG_KEXINIT message.
     */
    struct KeyExchangeInfo {
        int         packetSize;
        byte        cookie[16];
        std::string algorithms[MAX_ALGORITHM_COUNT];
        byte        follows;
        byte        paddingSize;
    };
};

#endif
