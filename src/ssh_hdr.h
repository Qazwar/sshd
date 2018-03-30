#ifndef _SSH_HDR_H_
#define _SSH_HDR_H_

/* project specific includes */
#include "types.h"

namespace ssh
{
    /* ssh_hdr
     * SSH packet header.
     */
#pragma pack(push, 1)
    struct ssh_hdr
    {
        uint32  packetSize;     /* packet length */
        byte    padding;        /* padding */
    };
#pragma pack(pop)

};

#endif