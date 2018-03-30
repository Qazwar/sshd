/* send.cpp
 * implements the send functionality of the transport layer.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#include "CTransport.h"
#include "debug.h"
#include "swap.h"
#include "errors.h"
#include <assert.h>

namespace ssh
{
    /* CTransport::sendPacket
     * Sends a packet to the remote host. Timeout is specified in milliseconds
     */
    int CTransport::sendPacket(int timeout)
    {
        int res = sendPacketNonblock(10);
        while( res == sshd_PACKET_PENDING ) {
            res = sendPacketNonblock(10);
        }

        return res;
    }

    /* CTransport::sendPacketNonblock
     * Sends a packet in non-blocking mode.
     */
    int CTransport::sendPacketNonblock(int timeout)
    {
        /* sequence number */
        uint32 seq;
        int res, wcount;
        if( sendState.state == sshd_STATE_NO_PACKET )
        {
            /*
             * Not currently sending anything.
             */
            initSendState( seq );       /* initialize the send state */
            sendCalcDigest( sendState.pData, sendState.dataSize, seq, sendState.pMac);
            sendEncryptData();          /* encrypt data */

            sendState.state = sshd_STATE_SENDING_PACKET;
        }
     
        if( sendState.state == sshd_STATE_SENDING_PACKET )
        {
            if( !ds->writePossible( timeout ) )
                return sshd_PACKET_PENDING;

            if( sendState.count < sendState.dataSize )
            {
                /* write the actual data */
                res = ds->writeBytes(sendState.pData + sendState.count, sendState.dataSize - sendState.count, &wcount);
                if( res != sshd_OK ) {
                    return sshd_ERROR;
                }
                else
                {
                    sendState.count += wcount;
                    if( sendState.count == sendState.dataSize )
                    {
                        /* entire packet has been sent */
                        sendState.state = sshd_STATE_NO_PACKET;
                        return sshd_OK;
                    } else {
                        return sshd_PACKET_PENDING;
                    }
                }
            } else {
                return sshd_OK;
            }
        }
        /* should not happen */
        return sshd_ERROR;
    }


    /* CTransport::initSendState
     * Prepare the transport layer to send
     */
    void CTransport::initSendState(uint32_t & seq)
    {
        uint32_t padding, mod;

        /* get the sequence number */
        seq = sendState.seq.update();

        /* the header is stored before the actual data in the byffer */
        sendState.pHdr      = (ssh::ssh_hdr *) sendState.pData;
        sendState.pPayload  = (sendState.pData + sizeof(ssh_hdr));      /* the payload is located after the header */
        sendState.pPad      = (sendState.pPayload + m_writePos);        /* the padding is located after the payload */
        
        sendState.blockSize     = (sendState.cipher ? sendState.cipher->GetBlockSize() : 8);
        sendState.payloadSize   = m_writePos;
        sendState.count         = 0;

        padding = 4;
        mod = (sendState.payloadSize + padding + sizeof(ssh_hdr)) % sendState.blockSize;

        if( mod != 0 ) {
            padding += sendState.blockSize - mod;
        }

        assert( padding <= 255 );

        sendState.pHdr->padding     = padding;
        sendState.pHdr->packetSize  = sendState.payloadSize + 1 + padding;
        sendState.pMac              = sendState.pPad + padding;                 /* digest is stored after the padding */

        /* store a copy of the last header */
        memcpy(&sendState.hdr , sendState.pHdr, sizeof( ssh_hdr ) );

        /* randomize the padding */
        randomizeData( sendState.pPad, padding );

        sendState.pHdr->packetSize  = __htonl32(sendState.pHdr->packetSize);
        sendState.dataSize          = sendState.payloadSize + sizeof(ssh_hdr) + padding;
    }

    /* CTransport::sendCalcDigest
     * Calculates the secure digest of the data and the sequence number.
     */
    void CTransport::sendCalcDigest(const byte * src, uint32_t len, uint32_t seq, byte * dst)
    {
        uint32_t dlen;
        if( sendState.hmac )
        {
            uint32 seq_be = __htonl32( seq );                                   /* sequence number must be in big endian */
            sendState.hmac->reinit();                                           /* reinitialize the digest */
            sendState.hmac->update((const byte *) &seq_be, sizeof( seq_be ));   /* add the sequence number */
            sendState.hmac->update(src, len);                                   /* add the packet contents */
            sendState.hmac->finalize(dst, &dlen);                               /* finalize the digest */

            sendState.dataSize += dlen;
        }
    }

    /* CTransport::sendEncryptData
     * Encrypts the data to be sent.
     */
    void CTransport::sendEncryptData()
    {
        if( sendState.cipher )
        {
            /* TODO: don't encrypt HMAC */
            uint32_t size = sendState.dataSize - (sendState.hmac ? sendState.hmac->GetDigestLength() : 0);
            sendState.cipher->Encrypt((const byte *) sendState.pHdr, (byte *) sendState.pHdr, size);
        }
    }
}