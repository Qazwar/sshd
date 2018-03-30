/* packets.cpp
 * Implements the functions that handles the SSH packets in the transport layer
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved
 */

/* project specific includes */
#include "CTransport.h"
#include "sshd.h"
#include "debug.h"
#include "ssh_hdr.h"
#include "messages.h"
#include "errors.h"

using namespace std;

namespace ssh
{
    /* CTransport::writeBytes
     * Writes data to the output buffer. Fails if insufficient space is available.
     */
    bool CTransport::writeBytes(const byte * src, int count)
    {
        if( sendState.state != sshd_STATE_NO_PACKET ) { /* incorrect state */
            return false;
        }
        if( (m_writePos + count) > 32000 ) { /* packet to large */
            return false;
        }
    
        if( (m_writePos + count) > sendState.bufSize ) {
            return false;
        }

        memcpy(&sendState.pPayload[m_writePos], src, count);
        sendState.payloadSize += count;
        m_writePos += count;
        return true;
    }

    /* CTransport::readBytes
     * Reads 'count' bytes from the input buffer. Fails if insufficient data is available.
     */
    bool CTransport::readBytes(byte * dst, int count)
    {
        if( (m_readPos + count) > readState.payloadSize ) {
            return false;
        }
        memcpy(dst, &readState.pPayload[m_readPos], count);
        m_readPos += count;
        return true;
    }

    /* CTransport::getPacketType
     * Returns the packet type of the packet in the input buffer.
     */
    bool CTransport::getPacketType(byte & id)
    {
        id = readState.pPayload[0];
        return true;
    }

    /* CTransport::flushPacket
     * Flushes the current packet
     */
    int CTransport::flushPacket(uint32_t timeout)
    {
        if( sendState.state != sshd_STATE_NO_PACKET ) {
            return sendPacket( timeout );
        } 
        return sshd_OK;
    }

    /* CTransport::newPacket
     *
     */
    void CTransport::newPacket()
    {
        sendState.state = sshd_STATE_NO_PACKET;
        m_writePos = 0;
    }

};