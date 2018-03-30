#ifndef _AES_H_
#define _AES_H_

/* project includes */
#include "CCipher.h"

#if defined(USE_OPENSSL)
#include <openssl/aes.h>
#else
#error No AES implementation available
#endif

namespace ssh
{
    /* aes
     * Advanced Encryption Standard (AES)
     */
    class aes : public CCipher
    {
    public: 
        aes(unsigned int);
        ~aes();

        /* initialization */
        bool EncryptInit(const byte *, const byte *);
        bool DecryptInit(const byte *, const byte *);
        /* encryption/decryption */
        void Encrypt(const byte *, byte *, int);
        void Decrypt(const byte *, byte *, int);
    
    private:
#if defined(USE_OPENSSL)
        unsigned char m_iv[AES_BLOCK_SIZE]; // 16 bytes IV
        AES_KEY m_key;
        unsigned int m_length;              /* the keylength */
#endif
    };
};

#endif