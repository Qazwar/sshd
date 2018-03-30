/* rsa.cpp
 * RSA implementation using OpenSSL
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "rsa.h"
#include "FileStream.h"
#include "ArrayStream.h"
#include "sha1.h"

/* C/C++ includes */
#include <string>
#include <assert.h>

#define MAX_RSA_KEYBLOB_LENGTH  (4096)
#define MIN_KEYBLOB_SIZE        (0)
#define MAX_KEYBLOB_SIZE        (4096)  

using namespace std;

namespace ssh
{
    /*
     *
     */
    rsa::rsa()
    {
        m_rsa = 0;
    }

    rsa::~rsa()
    {
        if( m_rsa )
            RSA_free( m_rsa );
    }

    /* loadKeys
     * Loads the keys.
     */
    bool rsa::loadKeys(const ssh::CSettings & settings)
    {
        string pub, priv;
        /* get the filenames from the settings */
        if( !settings.GetString(SSHD_SETTING_RSA_PUBLIC_KEY_FILE, pub) ||
            !settings.GetString(SSHD_SETTING_RSA_PRIVATE_KEY_FILE, priv) ) 
        {
            return false;
        }

        /* load the actual key-pair */
        if( !LoadKeyPair( pub.c_str(), priv.c_str() ) )
            return false;

        return true;
    }

    /* rsa::LoadKeyPair
     *
     */
    bool rsa::LoadKeyPair(const std::string & pub, const std::string & priv)
    {
        /* */
        return rsa::LoadKeyPair( pub.c_str(), priv.c_str() );
    }

    /* rsa::LoadKeys
     * Loads the public  key.
     */
    bool rsa::LoadKeyPair( const char * pub, const char * priv )
    {
        string ident;
        /* First load the public key */
        FileStream stream;

        if( !m_rsa )
            m_rsa = RSA_new();

        if( !stream.open( pub, FileStream::STREAM_MODE_READ) )
            return false;

        if( !stream.readString( ident ) || (ident != "rsa-pub") )
            return false;

#if defined( USE_OPENSSL )
        if( !stream.readBigInt( &m_rsa->n ) || !stream.readBigInt( &m_rsa->e ) )
            return false;
#else
#error No RSA implementation available
#endif

        /* Now open the private key file, which only stores the private exponent
           'd' since the modulos is shared
        */
        if( (stream.close(), !stream.open( priv, FileStream::STREAM_MODE_READ)) )
            return false;

        if( !stream.readString( ident ) || (ident != "rsa-priv") )
            return false;

#if defined( USE_OPENSSL )
        BIGNUM * n;
        if( !stream.readBigInt( &n ) )
            return false;

        if( BN_cmp(n, m_rsa->n) != 0 ) { /* verify that the exponent matches */
            BN_free( n );
            return false;
        }

        /* don't need it */
        BN_free(n);

        if( !stream.readBigInt( &m_rsa->d) )
            return false;
#else
#error No RSA implementation available
#endif
        return true;
    }

    /* rsa::ParseKeyblob
     * Parses the RSA keylob sent by the server.
     */
    bool rsa::ParseKeyblob( const byte * src, uint32 length )
    {
        string ident;
        if( !m_rsa )
            m_rsa = RSA_new();

        ArrayStream stream( src, length );

        if( !stream.readString(ident) || (ident != "ssh-rsa") ) 
            return false;

#ifdef USE_OPENSSL
        if( !stream.readBigInt( &m_rsa->e ) || !stream.readBigInt( &m_rsa->n ) )
            return false;
#else
#error No RSA implementation available
#endif
        return true;
    }

    /*
     * Parses the RSA keylob sent by the server.
     */
    bool rsa::ParseKeyblob(CStream & stream)
    {
        string ident;
        uint32_t len;

        if( !m_rsa )
            m_rsa = RSA_new();

        if( !stream.readInt32(len) || (len == 0) || (len > MAX_RSA_KEYBLOB_LENGTH) )
            return false;

        if( !stream.readString(ident) || (ident != "ssh-rsa") ) 
            return false;

#ifdef USE_OPENSSL
        if( !stream.readBigInt( &m_rsa->e ) || !stream.readBigInt( &m_rsa->n ) )
            return false;
#else
#error No RSA implementation available
#endif
        return true;
    }

    /*
     * Writes a keyblob containing the public RSA key
     */
    bool rsa::WriteKeyblob(ssh::CStream & stream)
    {
        unsigned char src[4096];
        ssh::ArrayWriteStream as( src, 4096 );
        if( !as.writeString( "ssh-rsa" ) ||     /* write identifier */
            !as.writeBigInt( m_rsa->e ) ||      /* write public key */
            !as.writeBigInt( m_rsa->n ) )
        {
            return false;
        }
        uint32_t length = as.GetUsage();
        /* packet begins with the blob length */
        if( !stream.writeInt32( length ) ||
            !stream.writeBytes( src, length ) )
        {
            return false;
        }
    
        return true;
    }

    /* 
     * rsa::ParseKeyblob
     * Parses the signature blob sent by the server
     */
    bool rsa::ParseSignature(CStream & stream)
    {
        string ident;
        uint32_t len, sigLen;

        if( !stream.readInt32(len) || (len < MIN_KEYBLOB_SIZE) || (len > MAX_KEYBLOB_SIZE) )
            return false;

        if( !stream.readString( ident ) || (ident != "ssh-rsa") )
            return false;

        if( !stream.readInt32(sigLen) || (sigLen == 0) || (sigLen > MAX_RSA_SIGNATURE_LENGTH) )
            return false;

        /* read the signature */
        if( !stream.readVector( m_signature, sigLen) )
            return false;

        return true;
    }

    /* rsa::ParseSignature
     * Parses the signature blob sent by the server
     */
    bool rsa::ParseSignature( const byte * src, uint32 length )
    {
        string ident;
        uint32 sigLen;

        if( !m_rsa )
            return false;

        ArrayStream stream(src, length);

        if( !stream.readString( ident ) || (ident != "ssh-rsa") )
            return false;

        if( !stream.readInt32(sigLen) || !sigLen || (sigLen > MAX_RSA_SIGNATURE_LENGTH) )
            return false;

        if( !stream.readVector( m_signature, sigLen ) )
            return false;

        return true;
    }

    /* rsa::WwriteSignature
     *
     */
    bool rsa::WriteSignature( ssh::CStream & stream, const std::vector<uint8_t> & sig)
    {
        /* calculate the size of the blob */
        size_t count = sig.size() + sizeof(uint32_t) + strlen("ssh-rsa") + 4;
        /* write the length */
        if( !stream.writeInt32( static_cast<uint32_t>(count) ) ||
            !stream.writeString( "ssh-rsa" ) ||
            !stream.writeInt32( sig.size() ) ||
            !stream.writeVector( sig ) )
        {
            return false;
        }

        return true;
    }

    /* rsa::VerifyHost
     * Verifies that the signature sent by the server matches the one calculcated
     * locally and signed with the server's public key.
     */
    bool rsa::VerifyHost( const std::vector<byte> & exchange )
    {
        int res;
        byte digest[ SHA1_DIGEST_LENGTH ];
        /* hash the exchange hash */
        sha1().hash( exchange, digest );

#ifdef USE_OPENSSL
        res = RSA_verify(NID_sha1, 
            digest, 
            SHA1_DIGEST_LENGTH,
            &m_signature[0],
            static_cast<unsigned int>(m_signature.size()),
            m_rsa);
#endif

        return (res == 1);
    }

    /* rsa::Sign
     * Signs the source data using the private RSA key.
     */
    bool rsa::Sign( const std::vector<byte> & src, std::vector<byte> & signature)
    {
        int res;
        unsigned int siglen;

        if( !m_rsa )
            return false;

        byte digest[ SHA1_DIGEST_LENGTH ];
        /* hash the exchange hash */
        sha1().hash( src, digest );

        /* resize the vector to stored the entire signature */
#if defined(USE_OPENSSL)
        signature.resize( RSA_size(m_rsa) );
        
        res = RSA_sign(NID_sha1,
            digest,
            SHA1_DIGEST_LENGTH,
            &signature[0],
            &siglen,
            m_rsa);
#endif
        return (res == 1);
    }

    /* rsa::writePublicKey
     * Writes the public key to the stream
     */
    bool rsa::WritePublicKey( CStream & stream )
    {
        assert(m_rsa != NULL);
        
        if( !stream.writeString("ssh-rsa") ||       /* identifier */
            !stream.writeBigInt(m_rsa->e) ||        
            !stream.writeBigInt(m_rsa->n) )
        {
            return false;
        }
        return true;
    }

    /* rsa::VerifySignature
     *
     */
    bool rsa::VerifySignature(const std::vector<byte> & key,        /* the supplied public key */
        const std::vector<byte> & data,                             /* the data */
        const std::vector<byte> & signature)                        /* signature over data */
    {
        int res;
        BIGNUM * n = NULL, * e = NULL;
        RSA * _rsa = RSA_new();
        if( !_rsa )
            return false;

        ArrayStream stream(&data[0], static_cast<uint32_t>(data.size()));
        
        /* read the public key */
        if( !stream.readBigInt(&n) || stream.readBigInt(&e) ) {
            if( n ) BN_free(n);
            if( e ) BN_free(e);
            if( _rsa ) RSA_free(_rsa);
            return false;
        }

        /* this will be dealloacted by RSA_free */
        _rsa->n = n;
        _rsa->e = e;

        vector<byte> sig = signature; /* hack, since the signature supplied to RSA_verify can't be const */

        res = RSA_verify(NID_sha1, 
            &data[0], 
            static_cast<unsigned int>(data.size()),
            &sig[0],
            static_cast<unsigned int>(sig.size()),
            _rsa);

        if( _rsa )
            RSA_free(_rsa);

        return (res == 1);
    }

    /* rsa::GenerateKeyPair
     *
     */
    bool rsa::GenerateKeyPair()
    {
        m_rsa = RSA_generate_key(2048, 65537, NULL, NULL);
        if( !m_rsa )
            return NULL;

        return true;
    }

    /* rsa::writePublicKey
     * Writes the public key to a file.
     */
    bool rsa::writePrivateKey(const char * filename)
    {
        ssh::FileStream stream;
        if( !stream.open( filename, FileStream::STREAM_MODE_WRITE ) )
        {
            return false;
        }
    
        /* write identifier */
        if( !stream.writeString("rsa-priv") )
            return false;

        if( !m_rsa ||!m_rsa->d || !m_rsa->e )
            return false;

        if( !stream.writeBigInt( m_rsa->n ) ||
            !stream.writeBigInt( m_rsa->d ) )
        {
            return false;
        }

        return true;
    }

    /* rsa::writePublicKey(const char * filename)
     * Writes the public key to a file.
     */
    bool rsa::writePublicKey(const char * filename)
    {
        ssh::FileStream stream;
        if( !stream.open( filename, FileStream::STREAM_MODE_WRITE ) )
        {
            return false;
        }

        /* write identifier */
        if( !stream.writeString("rsa-pub") )
            return false;

        if( !m_rsa ||!m_rsa->n || !m_rsa->e )
            return false;

        if( !stream.writeBigInt( m_rsa->n ) ||
            !stream.writeBigInt( m_rsa->e ) )
        {
            return false;
        }

        return true;
    }
};