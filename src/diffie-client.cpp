/* diffie-hellman.cpp
 * Implements the client part of the diffie-hellman keyexchange.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "CDiffieHellman.h"
#include "CTransport.h"
#include "messages.h"
#include "debug.h"
#include "errors.h"
#include "sshd.h"

namespace ssh
{
    /* CDiffieHellman::ClientKeyExchange
     * Performs the client side key exchange.
     */
    int CDiffieHellman::ClientKeyExchange(CHostKey * hostKey, bool guess)
    {
        /* first generate the keys */
        if( !GenerateKeys( false ) ) {
            return sshd_ERROR;
        }

        /* send the generated key to the client */
        m_ts->newPacket();
        if( !m_ts->writeByte(SSH_MSG_KEXDH_INIT) ||     /* write packet type */
            !m_e->write(*m_ts) )                        /* write 'e' to packet */ 
        {
            return sshd_ERROR;
        }

        /* Send the packet and wait for the server's reply */
        if( m_ts->exchangeAndExpect(SSH_MSG_KEXDH_REPLY) != sshd_OK )
        {
            return sshd_ERROR;
        }

        /* parse the reply */
        if( parseKexdhReply(hostKey) != sshd_OK ) {
            return sshd_ERROR;
        }

        /* check if the supplied key is valid */
        if( !validPublicKey(m_f) )
            return sshd_ERROR;

        /* compute the shared secret */
        if( !ComputeSecret(*m_f) ) {
            return sshd_ERROR;
        }

        /* calculate the exchange hash */
        if( !ComputeExchangeHash(m_exchange, hostKey) ) {
            return sshd_ERROR;
        }

        /* verify the server */
        if( !hostKey->VerifyHost(m_exchange)  ) {
            /* signature is invalid */
            sshd_Log(sshd_EVENT_FATAL, "Signature does not match the host's supplied key.");
            return sshd_ERROR;
        }

        /* the signature is valid */
        return sshd_OK; 
    }

    /* CDiffieHellman::parseKexdhReply
     * Parses the SSH_MSG_KEXDH_REPLY sent by the server
     */
    int CDiffieHellman::parseKexdhReply(CHostKey * hostKey)
    {
        uint8_t type;

        if( !m_ts->readByte(type) || (type != SSH_MSG_KEXDH_REPLY) ) 
        {
            return sshd_ERROR;
        }

        /* parse the keyblob from the stream */
        if( !hostKey->ParseKeyblob(*m_ts) )
            return sshd_ERROR;

        /* read the server's public key */
        if( !m_ts->readBigInt(&m_f) )
            return sshd_ERROR;

        /* read the signature */
        if( !hostKey->ParseSignature(*m_ts) ) {
            return sshd_ERROR;
        }

        return sshd_OK;
    }
}
