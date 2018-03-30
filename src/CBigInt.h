#ifndef _CBIGINT_H_
#define _CBIGINT_H_

#if defined(USE_OPENSSL)
#include <openssl/bn.h>
#endif

#include "CStream.h"

namespace ssh
{
    /* CBigInt
     * Wrapper class for large integer numbers, used during the keyexchange.
     */
    class CBigInt
    {
    public:
        CBigInt();
        ~CBigInt();

#if defined(USE_OPENSSL)
        CBigInt(BIGNUM *);
#endif
        bool write(CStream &) const; /* writes the integer to a stream */
        bool read(CStream &);        /* reads the value from a stream */
        const void * Native() const;

    protected:
#if defined(USE_OPENSSL)
        BIGNUM * m_bn;
#endif
    };
};

#endif