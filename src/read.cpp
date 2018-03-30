/* CTransport.cpp
 * Implements the transport layer functionality for reading SSH packets.
 *
 * Copyright (c) 2006-2007 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "CTransport.h"
#include "swap.h"
#include "messages.h"
#include "errors.h"
#include "sshd.h"

#include <assert.h>
#include <cstdio>

#define MAX_DIGEST_SIZE (64)
#define SSHD_MIN_PACKET_SIZE (8)
#define SSHD_MAX_PACKET_SIZE (32000)

namespace ssh
{

    /* CTransport::readPacket
     * Reads a packet from the remote host, timeout in milliseconds
     */
    int CTransport::readPacket(int timeout)
    {
        int res = readPacketNonblock(10);

        while( res == sshd_PACKET_PENDING || res == sshd_NO_PACKET ) {
            res = readPacketNonblock(10);
            /* check for abort event */
            sshd_CheckAbortEvent()
        }
        return res;
    }

    /* CTransport::readPacketNonblock
     * Reads a packet in non-blocking mode.
     */
    int CTransport::readPacketNonblock(int timeout)
    {
        int         res, count;
        uint8_t     type;

        //ssh_hdr * pHdr = (ssh_hdr *) readState.pData;

        /* check if any data is available */
        if( !ds->dataAvailable( timeout ) )
        {
            if( readState.state == sshd_STATE_NO_PACKET )
                return sshd_NO_PACKET;
    
            return sshd_PACKET_PENDING;
        }

        if( readState.state == sshd_STATE_NO_PACKET )
        {
            readState.state     = sshd_STATE_FIRST_BLOCK;
            readState.dataSize  = 0;
            readState.count     = 0;
            readState.blockSize = (readState.cipher ? readState.cipher->GetBlockSize() : 8);
            readState.pHdr      = (ssh_hdr *) readState.pData;

            m_readPos = 0;
        }

        if( readState.state == sshd_STATE_FIRST_BLOCK )
        {
            /* currently reading the first block of the packet */
            if( readState.count < readState.blockSize )
            {
                /* havent read the first block yet */
                res = ds->readBytes( readState.pData + readState.count, readState.blockSize - readState.count, &count);
                if( res != sshd_OK ) {
                    return res;
                }
                readState.count += count;
            }

            if( readState.count == readState.blockSize )
            {
                if( readState.cipher )
                {
                    /* decrypt first block */
                    readState.cipher->Decrypt(readState.pData, readState.pData, readState.blockSize);
                    /* size is stored as big endian */
                }

                readState.hdr.packetSize    = __ntohl32(readState.pHdr->packetSize);
                readState.hdr.padding       = readState.pHdr->padding;

                if( readState.hdr.packetSize < SSHD_MIN_PACKET_SIZE ||
                    readState.hdr.packetSize > SSHD_MAX_PACKET_SIZE )
                {
                    /* May be a decryption problem */
                    sshd_Log(sshd_EVENT_FATAL, "Invalid packet size, possibly a decryption error.");
                    return sshd_PROTOCOL_ERROR;
                }

                if( readState.hdr.padding < 4 )
                {
                    sshd_Log(sshd_EVENT_FATAL, "Invalid amount of padding in received packet.");
                    return sshd_PROTOCOL_ERROR;
                }
        
                /* calculate the packet size */
                readState.dataSize = readState.hdr.packetSize + sizeof(uint32_t);
                if( readState.dataSize % readState.blockSize ) {
                    sshd_Log(sshd_EVENT_FATAL, "Packet size not a multiple of the block size.");
                    return sshd_PROTOCOL_ERROR;
                }

                if( readState.hmac )
                    readState.dataSize += readState.hmac->GetDigestLength();
    
                /* set pointers */
                readState.pPayload  = (readState.pData + sizeof(ssh_hdr));                          
                readState.pPad      = readState.pPayload + readState.hdr.packetSize - readState.hdr.padding - 1;
                readState.pMac      = readState.pPad + readState.hdr.padding;
                readState.payloadSize   = readState.hdr.packetSize - readState.hdr.padding - 1;
            
                readState.state = sshd_STATE_READING_PACKET;
            } else {
                return sshd_PACKET_PENDING;
            }
        }

        if( readState.state == sshd_STATE_READING_PACKET )
        {
            int actual;
            uint8_t * dst = readState.pData + readState.count;
            /* read the data */
            res = ds->readBytes(dst, readState.dataSize - readState.count, &actual);
            if( res != sshd_OK )
                return sshd_ERROR;

            readState.count += actual;
            if( readState.count == readState.dataSize ) {
                readState.state = sshd_STATE_FINALIZE;
            } else {
                return sshd_PACKET_PENDING;
            }
        }

        if( readState.state == sshd_STATE_FINALIZE )
        {
            /* get the sequence number */
            uint32_t seq = readState.seq.update();
            seq = __htonl32( seq ); 

            /* decrypt the rest of the packet if required */
            if( readState.cipher )
            {
                /*
                 * We have already decrypted the first block.
                 */
                int count = readState.dataSize - (readState.hmac ? readState.hmac->GetDigestLength() : 0) - readState.blockSize;
                assert(count >= 0);
                if( count  > 0) 
                {
                    readState.cipher->Decrypt( readState.pData + readState.blockSize, readState.pData + readState.blockSize, count );
                }
            }

            /* calculate digest */
            if( readState.hmac )
            {
                unsigned char digest[64];
                uint32_t diglen;

                readState.hmac->reinit();
                readState.hmac->update((const byte *) &seq, sizeof(uint32_t));
                readState.hmac->update( readState.pData, readState.dataSize - readState.hmac->GetDigestLength() );
                readState.hmac->finalize( digest, &diglen );
                /* compare the calculated digest with the one supplied */

                if( memcmp( digest, readState.pMac, diglen ) != 0 )
                {
                    sshd_Log(sshd_EVENT_FATAL, "HMAC missmatch.");
                    return sshd_ERROR;
                }
            }
            
            readState.state = sshd_STATE_NO_PACKET;
            type = readState.pPayload[0];
            if( type == SSH_MSG_IGNORE || type == SSH_MSG_DEBUG ) {
                /* no need to propagate these messages */
                return sshd_NO_PACKET;
            }

            return sshd_OK;
        }
        sshd_Log(sshd_EVENT_FATAL, "Unexpected state encountered.");
        return sshd_ERROR;
    }
};