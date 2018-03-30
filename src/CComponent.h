#ifndef _CCOMPONENT_H_
#define _CCOMPONENT_H_

/* C/C++ includes */
#include <string>

/* project specific includes */
#include "types.h"

namespace ssh 
{
    /* Class:           CComponent
     * Description:     Baseclass for the different components.
     */
    class CComponent
    {
    public:
        virtual CComponent & setBlockingMode(bool)      = 0;
        virtual bool dataAvailable(int)                 = 0;
        virtual bool writePossible(int)                 = 0;
        virtual bool writeLine(const std::string &)     = 0;
        virtual bool readLine(std::string &)            = 0;
        virtual int readBytes(byte *, int)              = 0;
        virtual int writeBytes(const byte *, int)       = 0;
        virtual void disconnect()                       = 0;
    };
};

#endif