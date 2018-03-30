#include "CClientTransport.h"
#include "CKeyExchange.h"
#include "reasons.h"
#include "messages.h"
#include "errors.h"
#include "sshd.h"

/* C/C++ includes */
#include <string>

/* Boost */
#include <boost/shared_ptr.hpp>

using namespace std;

namespace ssh
{
    /* CClientTransport::mainTask
     * Primary task function for the client connection.
     */
    void CClientTransport::mainTask()
    {
        int res;
        
        sshd_Log(sshd_EVENT_NOTIFY, "Performing authentication.");

        /* perform authentication */
        res = performAuthentication();
        if( res != sshd_OK ) {
            setStatus(sshd_STATUS_FAILURE);
            return;
        }

        sshd_Log(sshd_EVENT_NOTIFY, "Áuthenticated.");

        if( !m_pService ) {
            sshd_Log(sshd_EVENT_FATAL, "No service specified.");
            setStatus(sshd_STATUS_FAILURE);
            return;
        }

        /* now request the service */
        res = requestService( m_pService->GetServiceName() );
        if( res != sshd_OK ) {
            setStatus(sshd_STATUS_FAILURE);
            return;
        }
        /* notify the service that it has been accepted by the server */
        m_pService->OnAccept();
        setStatus(sshd_STATUS_CONNECTED);

        while( 1 )
        {
            if( sshd_CheckAbortEvent_NoRet() ) {
                sshd_Log(sshd_EVENT_NOTIFY, "Connection closed by user.");
                disconnect( SSH_DISCONNECT_BY_APPLICATION );
                return;
            }
        
            /* output */
            if( sendState.state != sshd_STATE_NO_PACKET ) /* currently sending a packet */
            {
                res = sendPacketNonblock();
                if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to send packet.");
                    disconnect( SSH_DISCONNECT_PROTOCOL_ERROR );
                    return;
                }
            } else if( m_pService ) { /* check if the service has anything to send */

                if( m_pService->isDataAvailable( 0 ) )
                {
                    m_pService->read( sendState.pPayload, MAX_SSH_PAYLOAD, &sendState.payloadSize);
                    m_writePos = sendState.payloadSize;
                    res = sendPacketNonblock();
                    if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to send packet.");
                        return;
                    }
                }
            }

            /* Input */
            res = readPacketNonblock();
            if( res == sshd_OK )
            {
                /* we have read a packet */
                if( isTransportPacket() ) {
                    /* transport layer message */
                    res = handleTransportPacket();
                    if( res != sshd_OK ) {
                        return;
                    }
                } else {
                    /* let the service handle any other messages */
                    res = m_pService->handle( readState.pPayload, readState.payloadSize );
                    if( res != sshd_OK ) {
                        sshd_Log(sshd_EVENT_FATAL, "Error while handling reply.");
                        return;
                    }
                }
            } else if( (res != sshd_NO_PACKET) && (res != sshd_PACKET_PENDING) ) {
                sshd_Log(sshd_EVENT_FATAL, "Failed to read packet.");
                return;
            }
        }
    }

    /* CClientTransport::performAuthentication
     * Performs the client authentication.
     */
    int CClientTransport::performAuthentication()
    {
        int res;
        /* request the authentication service */
        res = requestService( m_iAuth->getAuthServiceName() );
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to request authentication service.");
            return sshd_ERROR;
        }
        /* now perform the actual authentication */
        while( 1 )
        {
            /* check for abort event */
            sshd_CheckAbortEvent()

            /* input */
            res = readPacketNonblock();
            if( res == sshd_OK ) {  /* handle the message */
                if( isTransportPacket() ) {
                    /* transport layer packet */
                    res = handleTransportPacket();
                    if( res != sshd_OK )
                        return res;
                } else {
                    res = handleAuthPacket();
                    if( res == sshd_CLIENT_AUTHENTICATED ) {
                        /* the client was authenticated */
                        sshd_Log(sshd_EVENT_NOTIFY, "The client is authenticated.");
                        return sshd_OK;
                    } 
                    else if( res != sshd_OK ) {
                        return sshd_ERROR;
                    }
                }
            } else if( (res != sshd_NO_PACKET) && (res != sshd_PACKET_PENDING) ) {
                sshd_Log(sshd_EVENT_FATAL, "Error while reading authentication packet.");
                return sshd_ERROR;
            }

            /* output */
            if( sendState.state != sshd_STATE_NO_PACKET )
            {
                res = sendPacketNonblock();
                if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to read authentication packet.");
                    return sshd_ERROR;
                }
            }
            else if( m_iAuth->authIsDataAvailable() ) /* data is available to be sent */
            {
                uint32_t dw;

                newPacket();
                /* read a packet from the authentication service */
                if( m_iAuth->authReadPacket( sendState.pPayload, MAX_SSH_PAYLOAD, &dw) != sshd_OK ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to read data from authentication service.");
                    return sshd_ERROR;
                }
                m_writePos = dw;
                /* now send the packet */
                res = sendPacketNonblock();
                if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to read authentication packet.");
                    return sshd_ERROR;
                }
            }
        }
        return sshd_ERROR;
    }

    /* CClientTransport::handleAuthPacket
     *
     */
    int CClientTransport::handleAuthPacket()
    {
        uint8_t type;
        int res;

        getPacketType(type);
        switch( type )
        {
        case SSH_MSG_USERAUTH_BANNER:       /* authentication banner */
            {
                m_iAuth->onAuthBanner();
            }
            break;
        case SSH_MSG_USERAUTH_FAILURE:      /* authentication attempt failed */
            {
                m_iAuth->onAuthFailure();
            }
            break;
        case SSH_MSG_USERAUTH_SUCCESS:      /* authentication attempt successful */
            {
                m_iAuth->onAuthSuccess();
                return sshd_CLIENT_AUTHENTICATED;
            }
            break;
        default:
            {
                if( type >= 60 && type <= 79 ) /* messages specific to the authentication method */ 
                {
                    res = m_iAuth->authWritePacket(readState.pPayload, readState.payloadSize);
                    if( res != sshd_OK ) {
                        return sshd_ERROR;
                    }
                } else {
                    return sshd_ERROR;
                }
            }
        }
        return sshd_OK;
    }

    /* CClientTransport::requestService
     * Requests a service.
     */
    int CClientTransport::requestService(const std::string & name)
    {
        int res;
        uint8_t type;

        /* first send the service request */
        newPacket();
        if( !writeByte(SSH_MSG_SERVICE_REQUEST) ||
            !writeString(name) )
        {
            return sshd_ERROR;
        }

        res = sendPacket();
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "Failed to send service request");
            return res;
        }
        /* wait for a reply */
        while( 1 )
        {
            res = readPacket();
            if( res != sshd_OK ) {

                sshd_Log(sshd_EVENT_FATAL, "Failed to read reply.");
                return res;
            }
            /* got a packet */
            getPacketType( type );
            switch( type )
            {
            case SSH_MSG_SERVICE_ACCEPT: /* read packet and verify it */
                {
                    uint8_t msg;
                    string service;
                    if( !readByte(msg) || !readString(service) || (service != name) )
                    {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to read reply.");
                        return sshd_ERROR;
                    }
                    /* service accepted */
                    return sshd_OK;
                }
            default:
                return sshd_ERROR;
            }
        }
    }

    /* CClientTransport::handleTransportPacket
     * Handles a transport layer packet.
     */
    int CClientTransport::handleTransportPacket()
    {
        uint8_t type;
        int res;

        getPacketType( type );
        switch( type )
        {
        case SSH_MSG_KEXINIT:
            {
                /* not the initial keyexchange, and the client wasn't the part that initiated the keyexchange */
                res = performKeyExchange( false, false );
                if( res != sshd_OK ) {
                    sshd_Log(sshd_EVENT_FATAL, "Keyexchange failed.");
                    return res;
                }
                return sshd_OK; /* keyexchange successful */
            }
        default:
            break;
        }

        return sshd_ERROR;
    }
};