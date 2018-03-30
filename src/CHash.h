#ifndef _CHASH_H_
#define _CHASH_H_

#if defined(USE_OPENSSL)
#include <openssl/evp.h>
#endif

#include "types.h"
#include <vector>

namespace ssh
{
    /* CHash
     * Baseclass for the message digest algorithms
     */
    class CHash
    {
    public:
#if defined(USE_OPENSSL)
        CHash(const EVP_MD * evp);
#endif
        ~CHash();
        virtual void update(const byte *, unsigned int);
        virtual void finalize(byte * digest, unsigned int *);
        virtual void finalize(std::vector<byte> &);
        virtual void reinit();
        virtual unsigned int length() {return EVP_MD_size(m_evp);}

        void hash( const std::vector<byte> &, byte * );

        static CHash * CreateInstance(const char *);
        static CHash * CreateInstance(const std::string &);

#if defined(USE_OPENSSL)
        EVP_MD_CTX md;
        const EVP_MD * m_evp;
#endif
    };
};

#endif