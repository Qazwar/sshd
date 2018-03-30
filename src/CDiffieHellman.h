#ifndef _CDIFFIEHELLMAN_H_
#define _CDIFFIEHELLMAN_H_

#define WIN32_LEAN_AND_MEAN

#if defined(USE_OPENSSL)
#include <openssl/dh.h>
#include <openssl/engine.h>
#else
#error No cryptographic packet specified.
#endif

#include "CKeyExchange.h"

namespace ssh
{
    /* CDiffieHellman
     * Diffie-Hellman keyexchange.
     */
    class CDiffieHellman : public CKeyExchange
    {
    public:
        CDiffieHellman(CTransport *, const char * prime, const char * generator);
        ~CDiffieHellman();

        int ServerKeyExchange(CHostKey *, bool guess);
        int ClientKeyExchange(CHostKey *, bool guess);

        /* returns the name of the hash used by the keyexchange */
        const char * GetHash() const {return "sha1";}
    protected:
        bool GenerateKeys(bool server);
        bool ComputeSecret(CBigInt &);
        bool ComputeExchangeHash(std::vector<byte> &, CHostKey *);
        bool Sign(CHostKey *, const std::vector<byte> &, std::vector<byte> &);
        int parseKexdhReply(CHostKey *);

        /* key validation */
        bool validPublicKey(const CBigInt *);
        bool validPrivateKey();

        const char * m_p, * m_g;
        CBigInt * m_e , * m_f;
        byte * key;

#if defined(USE_OPENSSL)
        DH * m_dh;      /* OpenSSL DiffieHellman */
        byte * m_key;   /* buffer to store the secret key */
        int m_size;     /* size of the secret key */
#endif
    };
};

#endif