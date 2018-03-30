#ifndef _CALGORITHM_H_
#define _CALGORITHM_H_

/* C/C++ includes */
#include <string>

namespace ssh
{
    class CTransport;

    /* CAlgorithm
     * 
     */
    class CAlgorithm
    {
    public:
        virtual ~CAlgorithm() {}
        enum
        {
            CIPHER,
            HMAC,
            COMPRESSION,
            HOSTKEY,
            HASH,
            KEYEXCHANGE
        };

        /* Creates a instance of the algorithm */
        static CAlgorithm * Create( const std::string &, int type, CTransport *);
        virtual int GetType() = 0;
    };
};

#endif