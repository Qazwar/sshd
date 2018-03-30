/* ServerTask.cpp
 * Implements the primary server task.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

#include "CServerTransport.h"
#include "sshd.h"
#include "messages.h"

/* c/c++ includes */
#include <string>

/* 
 * Definitions
 */

using namespace std;

namespace ssh
{
    /* CServerTransport::task
     * Perform the primary sshd task.
     */
    void CServerTransport::Task()
    {
        int res;

        if( sshd_CheckAbortEvent_NoRet() ) {
            sshd_Log(sshd_EVENT_NOTIFY, "Connection attempt aborted by user.");
            ds->disconnect();
            return;
        }

        /* establish the connection */
        res = establishConnection();
        if( res != sshd_OK ) {
            sshd_Log(sshd_EVENT_NOTIFY, "Failed to establish connection.");
            ds->disconnect();
            return;
        }

        /* run the primary task */
        mainTask();

        /* make sure to disconnect */
        ds->disconnect();
        sshd_Log(sshd_EVENT_NOTIFY, "Connection closed.");
    }

    /* CServerTransport::handlePacket
     *
     */
    int CServerTransport::handlePacket()
    {   
        uint8_t type, msg;
        int res;

        getPacketType( type );
        switch( type )
        {
        case SSH_MSG_SERVICE_REQUEST:
            {
                string serviceName;

                if( m_pService ) { /* a service has already been requested */
                    disconnect( SSH_DISCONNECT_PROTOCOL_ERROR );
                    return sshd_ERROR;
                } else {
                    if( !readByte( msg ) ||
                        (msg != type) ||
                        !readString( serviceName ) )
                    {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to parse packet.");
                        disconnect( SSH_DISCONNECT_PROTOCOL_ERROR );
                        return sshd_ERROR;
                    }

                    res = m_sshd->createService( serviceName, &m_pService );
                    if( res != sshd_OK ) {
                        if( res == sshd_NO_SUCH_SERVICE ) {
                            sshd_Log(sshd_EVENT_FATAL, "Unknown service requested.");
                            disconnect( SSH_DISCONNECT_SERVICE_NOT_AVAILABLE );
                            return res;
                        } else {
                            sshd_Log(sshd_EVENT_FATAL, "Failed to create requested service.");
                            disconnect( SSH_DISCONNECT_BY_APPLICATION );
                            return res;
                        }
                    }
                    /* the service has been created, notify it? */
                    return sshd_OK;
                }
                break;
            }
        case SSH_MSG_KEXINIT:
            {
                /* send any outgoing packet */
                if( sendState.state != sshd_STATE_NO_PACKET ) {
                    res = sendPacket();
                    if( res != sshd_OK )
                        return res;
                }
                sshd_Log(sshd_EVENT_NOTIFY, "Keyexchange triggered by remote host");
                /* perform the keyexchange */
                if( performKeyExchange() != sshd_OK )
                    return sshd_ERROR;

                return sshd_OK;
            }
        default:
            return sshd_ERROR;
        }
        /**/
        return sshd_ERROR;
    }

    /* CServerTransport::maintask
     *
     */
    void CServerTransport::mainTask()
    {
        int res;
        /* 
         * The first task the server needs to do is to authenticate the user.
         */
        if( performAuthentication() != sshd_OK ) {
            sshd_Log(sshd_EVENT_FATAL, "User authentication failed");
            return;
        }

        /*
         * The user has been authenticated
         */
        while( 1 )
        {

            /* poll if the connection has been closed */
            if( sshd_CheckAbortEvent_NoRet() ) {
                sshd_Log(sshd_EVENT_NOTIFY, "Connection has been closed by user.");
                disconnect( SSH_DISCONNECT_BY_APPLICATION );
                return;
            }

            /* try to send any currently outgoing packet */
            if( sendState.state != sshd_STATE_NO_PACKET )
            {
                res = sendPacketNonblock();
                if( (res != sshd_PACKET_PENDING) && (res != sshd_OK) ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to send outgoing packet.");
                    return;
                }
            } else if( m_pService )     /* check if the service has anything to send */
            {
                if( m_pService->isDataAvailable( 0 ) )
                {
                    uint32_t wrt = 0;
                    /* read the data from the service to the output buffer */
                    if( m_pService->read( sendState.pPayload, MAX_SSH_PAYLOAD, &wrt ) != sshd_OK )
                    {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to read data from service.");
                        disconnect( SSH_DISCONNECT_BY_APPLICATION );
                        return;
                    }
                    /* check the size here? */
                    m_writePos = wrt;
                    /* start sending the packet */
                    res = sendPacketNonblock();
                    if( (res != sshd_OK) && (res != sshd_PACKET_PENDING) ) {
                        sshd_Log(sshd_EVENT_FATAL, "Failed to send service data.");
                        disconnect( SSH_DISCONNECT_BY_APPLICATION );
                        return;
                    }
                }
            }

            /* handle any incoming packet */
            res = readPacketNonblock();
            if( res == sshd_OK ) {
                res = handlePacket();
                if( res != sshd_OK ) {
                    sshd_Log(sshd_EVENT_FATAL, "handlePacket() failed.");
                    return;
                }
            }
            else if( (res != sshd_NO_PACKET) && (res != sshd_PACKET_PENDING) ) {
                sshd_Log(sshd_EVENT_FATAL, "Failed to read packet.");
                return;
            }
        }
    }

};