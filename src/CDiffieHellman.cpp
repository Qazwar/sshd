/* CDiffieHellman
 * Diffie-Hellman keyexchange implementation
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "CDiffieHellman.h"
#include "sshd.h"
#include "CTransport.h"
#include "debug.h"
#include "CHashStream.h"
#include "messages.h"       /* SSH messages */
#include "sha1.h"

namespace ssh
{
    /* CDiffieHellman::CDiffieHellman
     *
     */
    CDiffieHellman::CDiffieHellman(CTransport * ts, const char * prime, const char * generator) : CKeyExchange(ts)
    {
#if defined(USE_OPENSSL)
        m_dh        = NULL;
        m_key       = NULL;
        m_e         = NULL;
        m_f         = NULL;
#endif
        m_p         = prime;
        m_g         = generator;

        m_secret    = NULL;
    }

    /* CDiffieHellman::~CDiffieHellman
     * Destructor, performs the required cleanup
     */
    CDiffieHellman::~CDiffieHellman()
    {
#if defined(USE_OPENSSL)
        if( m_dh )
            DH_free(m_dh);
        if( m_key ) 
            delete [] m_key;
#endif
        if( m_e )
            delete m_e;
        if( m_f )
            delete m_f;
        if( m_secret )
            delete m_secret;
    }

    /* CDiffieHellman::GenerateKeys
     * Generates the Diffie-Hellman keys.
     */
    bool CDiffieHellman::GenerateKeys(bool server)
    {
        int attempts = 0;
        bool valid = false;

#if defined(USE_OPENSSL)
        do
        {
            if( m_dh )
                DH_free(m_dh);

            if( !(m_dh = DH_new()) )
                return false;
    
            // first convert the large prime
            if(!BN_hex2bn(&m_dh->p,m_p)) {
                DH_free(m_dh); m_dh = 0;
                return false;
            }
            // now convert the generator
            if(!BN_hex2bn(&m_dh->g,this->m_g)) {
                DH_free(m_dh); m_dh = 0;
                return false;
            }
            // now generate the key.
            if(!DH_generate_key(m_dh)) {
                DH_free(m_dh); m_dh = 0;
                return false;
            }

            valid = validPrivateKey();
        } while( !valid && (attempts++) < 10);

        if( !valid )
            return false;

        if( server )
        {
            if( !(m_f = new (std::nothrow) CBigInt(m_dh->pub_key)) )
                return false;
        } else {
            if( !(m_e = new (std::nothrow) CBigInt(m_dh->pub_key)) )
                return false;
        }   
        return true;
#else
        return false;
#endif
    }

    /* CDiffieHellman::ComputeSecret
     * Calculates the shared secret.
     */
    bool CDiffieHellman::ComputeSecret(CBigInt & pub_key)
    {
        int res;
        char buf[1024];
        BIGNUM * bn;

#if defined(USE_OPENSSL)
        key = new (std::nothrow) byte[DH_size(m_dh)];
        if( !key ) {
            DBG("Memory allocation failed.");
            return false;
        }

        res = DH_compute_key(key, (const BIGNUM *)pub_key.Native(), m_dh);
        if( res == -1 ) {
            unsigned long e = ERR_get_error();
            ERR_error_string(e, buf);
            DBG("DH_Compute_key failed.");
            delete []key;
            return false;
        }

        bn = BN_bin2bn(key, res, NULL);
        delete [] key;

        if( !bn )
            return false;

        m_secret = new CBigInt( bn );
        if( !m_secret ) {
            BN_free( bn);
            return false;
        }
        BN_free( bn );

        m_size = res;   /* the size of the shared secret */
        return true;
#else
        return false;
#endif
    }

    /* CDiffieHellman::ComputeExchangeHash
     * Calculates the exchange hash.
     */
    bool CDiffieHellman::ComputeExchangeHash(
        std::vector<byte> & exchange, 
        CHostKey * hostkey)
    {
        /* get the keyexchange information */
        const KeyExchangeInfo & serverKex = m_ts->getServerKex();
        const KeyExchangeInfo & clientKex = m_ts->getClientKex();
    
        /* get the protocol version strings */
        const std::string & clientProtocolString = m_ts->getClientProtocolString();
        const std::string & serverProtocolString = m_ts->getServerProtocolString();

        CHashStream hash("sha1");
        if( !hash )
            return false;

        /* write everything to the hash */
        if( !hash.writeString(clientProtocolString) || 
            !hash.writeString(serverProtocolString) ||
            !hash.writeInt32(clientKex.packetSize - clientKex.paddingSize - 1) || /* ignored by the writeKex method */
            !hash.writeKex(clientKex) ||
            !hash.writeInt32(serverKex.packetSize - serverKex.paddingSize - 1) ||
            !hash.writeKex(serverKex) ||
            !hostkey->WriteKeyblob(hash) ||
            !m_e->write(hash) ||                /* write the client's public key */
            !m_f->write(hash) ||                /* write the server's public key */
            !m_secret->write(hash))             /* write the shared secret */
        {
            return false;
        }
        /* resize the vector to fit the digest and then finalize the hash */
        hash.finalize(exchange);
        return true;
    }

    /* CDiffieHellman::Sign
     * Signs the exchange hash using the server's private key.
     */
    bool CDiffieHellman::Sign(CHostKey * hostkey,
        const std::vector<byte> & exchange,
        std::vector<byte> & signature
        )
    {
        return hostkey->Sign( m_exchange, signature);
    }

    /* CDiffieHellman::validPrivateKey
     * Returns true if the generated private key is valid.
     */
    bool CDiffieHellman::validPrivateKey()
    {   
#if defined(USE_OPENSSL)
        int i, bits_set;
        assert( m_dh->priv_key != NULL );
        for(i = 0, bits_set = 0; i <= BN_num_bits(m_dh->priv_key); i++)
            if (BN_is_bit_set(m_dh->priv_key, i))
                ++bits_set;
        if( bits_set > 1 )
            return true;
        
        return false;
#else
        return false;
#endif
    }

    /* CDiffieHellman::validPublicKey
     * Returns true if the supplied public key is valid.
     */
    bool CDiffieHellman::validPublicKey(const CBigInt * pubKey)
    {
        int i, bits_set = 0, numBits, res;
#if defined(USE_OPENSSL)
        assert( pubKey != NULL );
        const BIGNUM * num = (const BIGNUM *) pubKey->Native();
        assert(num != NULL);
        for(i = 0, bits_set = 0, numBits = BN_num_bits(num); i <= numBits; i++) {
            if (BN_is_bit_set(num, i)) {
                ++bits_set;
            }
        }

        res = (BN_cmp(num, m_dh->p));
        return ((bits_set > 1) && (res == -1)); /* yes, this was borrowed from OpenSSH */
#else
        return false;   /* TODO */
#endif
    }
};

