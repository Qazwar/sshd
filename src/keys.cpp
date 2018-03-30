/* keys.cpp
 * Handles the SSH keys.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project specific includes */
#include "CTransport.h"
#include "sshd.h"           /* return values etc. */
#include "debug.h"
#include "CHashStream.h"
#include "errors.h"
#include "messages.h"

/*****************************************************************************/
/*                              DEFINITIONS                                  */
/*****************************************************************************/

using namespace std;

namespace ssh
{

    /* CTransport::DeriveKeys
     * Derives the required keys.
     */
    int CTransport::DeriveKeys
        (
        const ByteVector & ExchangeHash,
        const ByteVector & SessionIdentifier, 
        const CBigInt & SharedSecret,
        const char * hash,
        KeyVector & Keys
        ) const
    {
        int res;
        for(int i = 0; i < MAX_KEYS; i++) {
            if( (res = DeriveKey(ExchangeHash, SessionIdentifier, SharedSecret, hash, 'A' + i, Keys[i], MAX_KEY_LENGTH)) != sshd_OK ) {
                return res;
            }
        }
        return sshd_OK;
    }

    /* CTransport::DeriveKey
     * Derives a single key.
     */
    int CTransport::DeriveKey
        (
        const ByteVector & exchangeHash,        /* Exchange hash */
        const ByteVector & sessionIdentifier,   /* Session identifier */
        const CBigInt & sharedSecret,           /* The shared secret */
        const char * hash,                      /* name of hash method */
        char unique,                            /* unique character for this key */
        KeyElement & key,                       /* Key to derive */
        uint32_t length                             /* length of key do derive */
        ) const
    {
        byte buf[64 + 64];
        unsigned int dlen, count = 0;

        /* derive a single key */
        ssh::CHashStream stream( hash );
        if( !hash )
            return sshd_ERROR;  /* failed to initialize hash instance */

        if (!sharedSecret.write( stream ) ||        /* write the shared secret */
            !stream.writeVector( exchangeHash ) ||      /* write exchange hash */
            !stream.writeByte( unique ) ||              /* write the unique character */
            !stream.writeVector( sessionIdentifier) )   /* write the session identifier */
        {
            return sshd_ERROR;
        }

        stream.finalize( buf, &dlen );
        count += dlen;

        while( count < length )
        {
            stream.reset();
            if( !sharedSecret.write( stream ) ||
                !stream.writeVector( exchangeHash ) ||
                !stream.writeBytes( buf, count ) )
            {
                return sshd_ERROR;
            }
            stream.finalize( buf + count, &dlen );
            count += dlen;
        }
        /* copy the derived key */
        memcpy( key.key, buf, 32);
        return sshd_OK;
    }

    /* CTransport::createAlgorithmInstances
     *
     */
    int CTransport::createAlgorithmInstances( 
        const string names[MAX_ALGORITHM_COUNT],
        SecurityBlock & block )
    {
        memset(&block, 0, sizeof(SecurityBlock));

        if( names[ENCRYPTION_CLIENT_TO_SERVER] != "none" ) {
            if( !(block.enc_client_to_server = CCipher::CreateInstance( names[ENCRYPTION_CLIENT_TO_SERVER] )) )
                goto cleanup;
        }

        if( names[ENCRYPTION_SERVER_TO_CLIENT] != "none" ) {
            if( !(block.enc_server_to_client = CCipher::CreateInstance( names[ENCRYPTION_SERVER_TO_CLIENT] )) )
                goto cleanup;
        }

        if( names[MAC_CLIENT_TO_SERVER] != "none" ) {
            if( !(block.hmac_client_to_server = CHmac::CreateInstance( names[MAC_CLIENT_TO_SERVER] )) )
                goto cleanup;
        }

        if( names[MAC_SERVER_TO_CLIENT] != "none" ) {
            if( !(block.hmac_server_to_client = CHmac::CreateInstance( names[MAC_SERVER_TO_CLIENT] )) )
                goto cleanup;
        }

        return sshd_OK;

cleanup:

        delete block.enc_client_to_server;
        delete block.enc_server_to_client;
        delete block.hmac_client_to_server;
        delete block.hmac_server_to_client;

        return sshd_ERROR;
    }

    /* CTransport::TakeKeysIntoUse
     * Initializes the algorithms with the keys.
     */
    int CTransport::TakeKeysIntoUse(const KeyVector & vec, const string algorithms[MAX_ALGORITHM_COUNT])
    {
        int res;
        SecurityBlock block;

        res = createAlgorithmInstances( algorithms, block );
        if( res != sshd_OK ) {
            goto cleanup;
        }

        /* initialize the keys */
        InitializeKeys( block, vec );

        /* send a SSH_MSG_NEWKEYS message before using the new algorithms/keys */
        newPacket();
        if( !writeByte(SSH_MSG_NEWKEYS) )
            goto cleanup;

        if( exchangeAndExpect( SSH_MSG_NEWKEYS ) != sshd_OK )
            goto cleanup;

        /* take the algorithms/keys into use */
        res = TakeAlgorithmsInUse( block );
        if( res != sshd_OK )
            goto cleanup;

        return sshd_OK;

cleanup:
    
        delete block.enc_client_to_server;
        delete block.enc_server_to_client;
        delete block.hmac_client_to_server;
        delete block.hmac_server_to_client;

        return sshd_ERROR;
    }
};