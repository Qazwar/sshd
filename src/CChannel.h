/* CChannel.h
 * SSH channel implementation.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "BoundedBuffer.h"
#include "types.h"

#ifndef _CCHANNEL_H_
#define _CCHANNEL_H_

namespace ssh
{
    /* CChannel
     * SSH data channel.
     */
    class CChannel 
    {
    public:

    protected:
        Util::BoundedBuffer<uint8_t> * m_bufIn, * m_bufOut;
    };
};

#endif