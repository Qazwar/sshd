/* hmac_sha1.cpp
 *
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved
 */

#include "hmac_sha1.h"

namespace ssh
{
    /* */
    hmac_sha1::hmac_sha1()
    {
        m_digest = EVP_sha1();
        HMAC_CTX_init(&ctx);
    }

    /* */
    void hmac_sha1::Init(const byte * key)
    {
        HMAC_Init_ex(&ctx, key, GetKeyLength(), m_digest,0);
    }

    /* */
    void hmac_sha1::reinit()
    {
        HMAC_Init_ex(&ctx, 0, 0, 0,0);
    }

    /* */
    void hmac_sha1::update(const byte * data, uint32_t len)
    {
        HMAC_Update(&ctx, data, len);
    }

    /* */
    void hmac_sha1::finalize(byte * digest, uint32_t * len)
    {
        HMAC_Final(&ctx, digest, len);
    }

    /* */
    int hmac_sha1::GetDigestLength()
    {
        return SHA1_DIGEST_LENGTH;
    }

    /* */
    int hmac_sha1::GetKeyLength()
    {
        return SHA1_KEY_LENGTH;
    }
}