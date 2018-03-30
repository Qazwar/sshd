#ifndef _MESSAGEHANDLER_H_
#define _MESSAGEHANDLER_H_

#include "types.h"

namespace ssh
{
    /* MessageHandler
     *
     */
    class MessageHandler
    {
    public:
        virtual int process(byte, const byte *, int) = 0;
    };
};

#endif