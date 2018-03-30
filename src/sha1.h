#ifndef _SHA1_H_
#define _SHA1_H_

/* project includes */
#include "CHash.h"

/* defines */
#define SHA1_DIGEST_LENGTH (20)

namespace ssh
{
    /* sha1
     * SHA-1 implementation
     */
    class sha1 : public CHash
    {
    public:
#if defined(USE_OPENSSL)
        sha1() : CHash(EVP_sha1()) {
        }
#endif
    };
};

#endif