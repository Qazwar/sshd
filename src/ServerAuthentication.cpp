/* CServerTransport.cpp
 * Implements the server side authentication
 * 
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */
#include "CServerTransport.h"
#include "sshd.h"
#include "messages.h"
#include "debug.h"

/* standard includes */
#include <string>

using namespace std;

namespace ssh
{
    /* CServerTransport::performAuthentication
     * Performs the authentication.
     */
    int CServerTransport::performAuthentication()
    {
        int res;
        /* The first step in the authentication process is that the client
         * requests a authentication service.
         */
        m_authState = sshd_AUTH_STATE_WAIT_SERVICE_REQUEST;

        while( 1 )
        {
            sshd_CheckAbortEvent()
            /*
             * Incoming data.
             */
            res = readPacketNonblock(50);
            if( res == sshd_OK )
            {
                res = handleAuthPacket();
                if( res == sshd_CLIENT_AUTHENTICATED ) {
                    /* client has been authenticated */
                    return sshd_OK;
                } else if( res != sshd_OK ) {
                    /* authentication failure */
                    return res;
                }
            } else if( (res != sshd_PACKET_PENDING) && (res != sshd_NO_PACKET) ) {
                sshd_Log(sshd_EVENT_FATAL, "Failed to read packet");
                return sshd_ERROR;
            }

            /*
             * Outgoing data, check if we are currently sending a packet or check if we have data ready to be sent.
             */
            if( sendState.state != sshd_STATE_NO_PACKET ) { /* currently sending a packet */
                res = sendPacketNonblock();
                if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to send packet.");
                    return sshd_ERROR;
                }
            }
            else if( m_pAuthService )   /* check if the authentication service has anything to send */
            {
                if( m_pAuthService->isDataAvailable(0) ) 
                {
                    /* data available to be sent */
                    uint32_t wrt = 0;
                    res = m_pAuthService->read( sendState.pPayload, MAX_SSH_PAYLOAD, &wrt);
                    if( res == sshd_OK ) {
                        m_writePos = wrt;
                        res = sendPacketNonblock();
                        if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                            /* failed to send packet */
                            sshd_Log(sshd_EVENT_FATAL, "Failed to send authentication service message.");
                            disconnect( SSH_DISCONNECT_BY_APPLICATION );
                            return sshd_ERROR;
                        }
                    } else {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to read data from authentication service.");
                        disconnect( SSH_DISCONNECT_BY_APPLICATION );
                        return sshd_ERROR;
                    }
                }
            }
        }
        return sshd_ERROR;
    }

    /* CServerTransport::handleAuthPacket
     *
     */
    int CServerTransport::handleAuthPacket()
    {
        uint8_t id;
        int res = 0;

        getPacketType( id );
        switch( m_authState )
        {
        case sshd_AUTH_STATE_WAIT_SERVICE_REQUEST:
            {
                /*
                 * Initial state
                 */
                if( id == SSH_MSG_SERVICE_REQUEST )
                {
                    return tryHandleAuthServiceRequest();
                }
            }
            break;
        case sshd_AUTH_STATE_SERVICE_ACCEPT:
            {
                /*
                 * The client has requested a authentication service and the 
                 * request has been granted.
                 */
                if( id >= 60 && id <= 79 ) /* let the authentication service handle the packets */
                {
                    res = m_pAuthService->handle(readState.pPayload, readState.payloadSize);
                    if( res == sshd_CLIENT_AUTHENTICATED )
                    {
                        /* the client has been authenticated */
                        delete m_pAuthService;
                        m_pAuthService = 0;
                        /* notify client */
                        newPacket();
                        if( !writeByte( SSH_MSG_USERAUTH_SUCCESS ) ||
                            (sendPacket() != sshd_OK) )
                        {
                            sshd_Log(sshd_EVENT_FATAL, "Failed to write authentication success reply.");
                            return sshd_ERROR;
                        }
                        /* authenticated */
                        return sshd_CLIENT_AUTHENTICATED;
                    } else if( res != sshd_OK ) {
                        sshd_Log(sshd_EVENT_FATAL, "Authentication process failed.");
                        return sshd_ERROR;
                    }
                    return sshd_OK;
                } else {
                    sshd_Log(sshd_EVENT_FATAL, "Unexpected packet.");
                    return sshd_ERROR;
                }
            }
            break;
        default:
            sshd_Log(sshd_EVENT_FATAL, "Unknown authentication state.");
            return sshd_ERROR;
        }
        return sshd_ERROR;
    }

    /* CServerTransport::tryHandleAuthServiceRequest
     *
     */
    int CServerTransport::tryHandleAuthServiceRequest()
    {
        uint8_t type;
        string  service;
        int     res;

        /* read the packet */
        if( !readByte(type) ||
            !readString(service) ||
            (type != SSH_MSG_SERVICE_REQUEST) )
        {
            sshd_Log(sshd_EVENT_FATAL, "Failed to read service request message.");
            return sshd_PROTOCOL_ERROR;
        }
        /* check if the requested service exists */
        /* the services are registered to the sshd */

        res = m_sshd->createAuthService( service, this, &m_pAuthService );
        if( res == sshd_OK ) 
        {
            /* service created, write a reply */
            newPacket();
            if( !writeByte(SSH_MSG_SERVICE_ACCEPT) ||
                !writeString( service ) ||
                (sendPacket() != sshd_OK) ) 
            {
                sshd_Log(sshd_EVENT_FATAL, "Failed to send SSH_MSG_SERVICE_ACCEPT message.");
                return sshd_ERROR;
            }
            m_authState = sshd_AUTH_STATE_SERVICE_ACCEPT;
            return sshd_OK;
        } 
        else if( res == sshd_NO_SUCH_SERVICE )  /* no such service has been registered */
        {
            sshd_Log(sshd_EVENT_WARNING, "The requested service does not exist.");
            disconnect( SSH_DISCONNECT_SERVICE_NOT_AVAILABLE );
        } 
        else if( res == sshd_CLIENT_NOT_ALLOWED ) /* the client isn't allowed to use this service */
        {
            sshd_Log(sshd_EVENT_FATAL, "Service not available for connected user.");
            disconnect( SSH_DISCONNECT_SERVICE_NOT_AVAILABLE );
        }
        sshd_Log(sshd_EVENT_FATAL, "Failed to create authentication service.");
        return sshd_ERROR;
    }
}