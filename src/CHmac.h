#ifndef _CHMAC_H_
#define _CHMAC_H_

/* project includes */
#include "CAlgorithm.h"
#include "types.h"

namespace ssh 
{
    /* CHmac
     * Baseclass for the keyed MAC:s
     */
    class CHmac : public CAlgorithm
    {
    public:
        int GetType() {return CAlgorithm::HMAC;}

        /* initializes the mac with the key */
        virtual void Init(const byte * key)         = 0;
        virtual void reinit()                       = 0;
        virtual void update(const byte *, uint32_t) = 0;
        virtual void finalize(byte *, uint32_t *)   = 0;
        virtual int GetDigestLength()               = 0;

        static CHmac * CreateInstance( const std::string & );

    };
};

#endif