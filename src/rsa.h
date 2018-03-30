#ifndef _RSA_H_
#define _RSA_H_

/* project includes */
#include "CHostKey.h"

/* C/C++ includes */
#include <vector>

#if defined(USE_OPENSSL)
#include <openssl/rsa.h>
#endif

/* defines */
#define MAX_RSA_SIGNATURE_LENGTH (4096)

using namespace std;

namespace ssh
{
    /* rsa
     * RSA implementation.
     */
    class rsa : public CHostKey
    {
    public:
        rsa();
        ~rsa();

        /* loads a keypair from a file */
        bool LoadKeyPair(const char *, const char *);
        bool LoadKeyPair(const std::string &, const std::string &);

        /* generates a keypair */
        bool GenerateKeyPair();

        /* writes the public key to a file */
        bool writePublicKey(const char *);
        /* writes the private key to a file */
        bool writePrivateKey(const char *);
        /* writes a keyblob to the stream */
        bool WriteKeyblob( CStream & stream );

        /* Parses the keyblob sent by the server */
        bool ParseKeyblob( const byte *, uint32 );
        bool ParseKeyblob(CStream & stream);

        /* Parses the signature blob sent by the server */
        bool ParseSignature( const byte *, uint32 );
        bool ParseSignature(CStream & stream);
        /* */
        bool WriteSignature( CStream & stream, const std::vector<uint8_t> & );

        /* Verifies that the parsed signature matches */
        bool VerifyHost( const std::vector<byte> & exchange );
        bool Sign( const std::vector<byte> &, std::vector<byte> & );
        bool WritePublicKey( CStream & );
        /* loads the keypair */
        bool loadKeys(const ssh::CSettings &);
        
        static bool VerifySignature(const std::vector<byte> &, const std::vector<byte> &, const std::vector<byte> &);

    protected:
        RSA * m_rsa;
        std::vector<byte> m_signature;
    };
};

#endif