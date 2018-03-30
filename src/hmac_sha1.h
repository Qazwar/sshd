/* hmac_sha1.h
 *
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#ifndef _CHMAC_SHA1_H_
#define _CHMAC_SHA1_H_

#include <openssl/hmac.h>
#include "CHmac.h"


#define SHA1_KEY_LENGTH             (20)
#define SHA1_DIGEST_LENGTH          (20)

namespace ssh
{
    /* hmac_sha1
     * Data integrity using SHA1 (160-bit)
     */
    class hmac_sha1 : public CHmac
    {
    public:
        hmac_sha1();
        void Init(const byte * key);
        void reinit();
        void update(const byte *, uint32_t);
        void finalize(byte *, uint32_t *);
        int GetDigestLength();
        int GetKeyLength();
    protected:
        const EVP_MD * m_digest;
        HMAC_CTX ctx;
    };
}

#endif