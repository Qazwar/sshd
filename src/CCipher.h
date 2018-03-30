#ifndef _CCIPHER_H_
#define _CCIPHER_H_

/* project includes */
#include "types.h"
#include "CAlgorithm.h"

namespace ssh
{
    /* CCipher
     * Baseclass for the symmetric ciphers.
     */
    class CCipher : public CAlgorithm
    {
    public:
        virtual ~CCipher() { }

        int GetType() {return CAlgorithm::CIPHER;}

        /* initialization */
        virtual bool EncryptInit(const byte *, const byte *)    = 0;
        virtual bool DecryptInit(const byte *, const byte *)    = 0;
        /* encryption/decryption */
        virtual void Encrypt(const byte *, byte *, int)         = 0;
        virtual void Decrypt(const byte *, byte *, int)         = 0;
    
        uint32 GetBlockSize() {return m_blockSize;}

        static CCipher * CreateInstance( const std::string & );
    protected:
        uint32 m_blockSize;     /* the block size */
    };
};

#endif