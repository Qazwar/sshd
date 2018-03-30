#include "CHash.h"
#include <openssl/evp.h>

/* The different hash algorithms, used for the factory functions */
#include "sha1.h"

namespace ssh
{
#if defined(USE_OPENSSL)
    /* CHash::CHash
     * Performs the required initialization
     */
    CHash::CHash(const EVP_MD * evp) : m_evp(evp)
    {
        EVP_DigestInit(&md, evp);
    }
#endif

    /* CHash::~CHash
     * Performs the required cleanup
     */
    CHash::~CHash()
    {
#if defined(USE_OPENSSL)
        EVP_MD_CTX_cleanup(&md);
#endif
    }

    /* CHash::finalize
     * Finalizes the hash.
     */
    void CHash::finalize(byte *digest, unsigned int * num)
    {
#if defined(USE_OPENSSL)
        EVP_DigestFinal_ex(&md, digest, num);
#endif
    }

    /* CHash::finalize
     * Finalizes the hash and stores the contents in the vector.
     */
    void CHash::finalize(std::vector<byte> & vec)
    {
        unsigned int num;
        vec.resize( length() );
#if defined(USE_OPENSSL)
        finalize(&vec[0], &num); 
#endif
    }

    /* CHash::update
     * Updates the hash with data.
     */
    void CHash::update(const byte * src, unsigned int num)
    {
#if defined(USE_OPENSSL)
        EVP_DigestUpdate(&md, src, num);
#endif
    }

    /* CHash::reinit
     * Reinitializes the hash.
     */
    void CHash::reinit()
    {
#if defined(USE_OPENSSL)
        EVP_DigestInit(&md, m_evp);
#endif
    }

    /* CHash::hash
     * Hashes the contents of the vector and stores the digest in 'digest'.
     */
    void CHash::hash(const std::vector<byte> & src, byte * digest)
    {
        unsigned int dlen;
        reinit();
        update(&src[0], static_cast<unsigned int>(src.size()));
        finalize(digest, &dlen);
    }

    /* CHash::CreateInstance
     * Creates a new hash instance based on the name.
     */
    CHash * CHash::CreateInstance(const char * name)
    {
        if( !strcmp(name, "sha1") )
            return new (std::nothrow) sha1;
            
        return NULL;
    }

    /* CHash::CreateInstance
     * Creates a new hash instance based on the name.
     */
    CHash * CHash::CreateInstance(const std::string & name)
    {
        return CreateInstance( name.c_str() );
    }

};