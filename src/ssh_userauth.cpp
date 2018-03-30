/* ssh_userauth.cpp
 * Implements the ssh-userauth authentication protocol.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

#include "ssh_userauth.h"
#include "sshd.h"
#include "messages.h"
#include "ArrayStream.h"

/* standard includes */
#include <string>

using namespace std;

enum {
    SSHD_USERAUTH_NONE_AUTHENTICATION_ALLOWED           = (1 << 0),
    SSHD_USERAUTH_PASSWORD_AUTHENTICATION_ALLOWED       = (1 << 1),
    SSHD_USERAUTH_PK_AUTHENTICATION_ALLOWED             = (1 << 2),
    SSHD_USERAUTH_ENABLE_BOGUS_AUTHENTICATION           = (1 << 3),
    SSHD_USERAUTH_ALLOW_USERNAME_SERVICE_CHANGE         = (1 << 4)
};

namespace ssh
{
    /* ssh_userauth::init
     * Initializes the service based on the supplied settings.
     */
    bool ssh_userauth::init(const ssh::CSettings & settings)
    {
        m_settings = 0;
        int value;
        /* check if the authentication method 'none' is enabled */
        if(settings.GetValue(SSHD_SETTING_AUTHENTICATION_NONE, value) && (value == OK))
            m_settings |= SSHD_USERAUTH_NONE_AUTHENTICATION_ALLOWED;
        /* check if the authentication method 'password' is enabled */
        if(settings.GetValue(SSHD_SETTING_AUTHENTICATION_PASSWORD,value) && (value == OK))
            m_settings |= SSHD_USERAUTH_PASSWORD_AUTHENTICATION_ALLOWED;
        /* check if the authentication method "publickey" is enabled */
        if(settings.GetValue(SSHD_SETTING_AUTHENTICATION_PK, value) && (value == OK))
            m_settings |= SSHD_USERAUTH_PK_AUTHENTICATION_ALLOWED;
        /* check if the server should use bogus authentication when the username is incorrect */
        if(settings.GetValue(SSHD_SETTING_BOGUS_AUTHENTICATION, value)   && (value == OK))
            m_settings |= SSHD_USERAUTH_ENABLE_BOGUS_AUTHENTICATION;

        if(settings.GetValue(SSHD_SETTING_AUTHENTICATION_ATTEMPTS, value) && (value >= 1 && value <= 100) )
            m_maxAuthAttempts = value;
        else
            m_maxAuthAttempts = 20;

        return true;
    }

    /* ssh_userauth::handleAuthentication
     * Handle authentication messages
     */
    int ssh_userauth::handleAuthentication(const uint8_t * src, uint32_t count)
    {
        ssh::ArrayStream stream(src, count);
        uint8_t id;
        wstring userName;
        string service, method;
        int value, res;

        if( !stream.readByte(id) )
            return SSHD_AUTH_ERROR;

        switch( id )
        {
            /* 
             * The client sent a authentication request
             */
        case SSH_MSG_USERAUTH_REQUEST:
            {
                if( !stream.readUTF8(userName) ||       /* read the username */
                    !stream.readString(service) ||      /* read the service name */
                    !stream.readString(method) )        /* read the method */
                {
                    /* Failed to read request message */
                    return SSHD_AUTH_ERROR;
                }

                if( m_state != SSH_USERAUTH_STATE_INIT ) { 
                    /* A new userauth attempt while the old one is still pending */
                    flushState();
                }

                if( m_initialAttempt ) {
                    /* Initial authentication attempt */
                    orgUserName = userName;
                    orgService  = service;
                    m_initialAttempt = false;
                } else {
                    /* check if either the username of service has changed */
                    if( userName != orgUserName ||
                        service != orgService ) 
                    {
                        if( m_settings & SSHD_USERAUTH_ALLOW_USERNAME_SERVICE_CHANGE ) {
                            /* username/password changed, not allowed */
                            return SSHD_AUTH_ERROR;
                        } else {
                            /* flush the authentication state */
                            flushState();
                            orgUserName = userName;
                            orgService  = service;
                        }
                    }
                }

                res = performAuthentication( stream, method, userName, m_info);
                if( res == OK ) /* Authentication was successful */
                {
                    if( (m_info.authMask == 0) || ((m_authState & m_info.authMask) == m_info.authMask) ) {
                        /* full authentication */
                    } else {
                        /* partial authentication */
                    }
                } else { /* Authentication failed */
                    if( (++m_numAttempts) > m_maxAuthAttempts ) {
                        /* To many authentication attempts, close the connection */
                    } else {
                        /* send a SSH_MSG_USERAUTH_FAILURE reply with the remaining methods */
                        //m_nextMethods = (m_info.authMask);
                    }
                }
            }
            break;
        default:
            /* incorrect message at this time */
            break;
        }
        return SSHD_AUTH_OK;
    }

    /* ssh_userauth::performAuthentication
     * Performs the authentication.
     */
    int ssh_userauth::performAuthentication(CStream & stream, 
                                            const std::string & method, 
                                            const wstring & username, 
                                            const UserInfo & info)
    {
        int res = SSHD_AUTH_ERROR;
        /* Perform the requested authentication */
        if( method == "none" ) {            
            res = doNoneAuthentication( stream , username, info );
        } 
        else if( method == "password" ) {
            res = doPasswordAuthentication( stream, username, info );
        } 
        else if( method == "publickey" ) {  
        }
        else {
            return SSHD_AUTH_ERROR;
        }
        return res;
    }

    /* ssh_userauth::flushState
     * Flushes the current authentication state.
     */
    void ssh_userauth::flushState()
    {
    }

    /* ssh_userauth::doNoneAuthentication
     * Performs the 'none' authentication method defined in ssh-userauth.
     */
    int ssh_userauth::doNoneAuthentication( CStream & stream, 
                                            const std::wstring & userName, 
                                            const UserInfo & info )
    {
        int value;
        if( !(m_settings & SSHD_USERAUTH_NONE_AUTHENTICATION_ALLOWED) ) {
            /* Authentication method not supported */
            return SSHD_AUTH_METHOD_NOT_ALLOWED;
        }
        /* User authenticated */
        return SSHD_AUTH_SUCCESS;
    }

    /* ssh_userauth::doPasswordAuthentication
     * Performs the 'password' authentication method defined in ssh-userauth.
     */
    int ssh_userauth::doPasswordAuthentication( CStream & stream,
                                                const std::wstring & username,
                                                const UserInfo & info )
    {
        int value;
        if( m_settings & SSHD_USERAUTH_PASSWORD_AUTHENTICATION_ALLOWED ) {
            /* Authentication method not supported */
            return SSHD_AUTH_METHOD_NOT_ALLOWED;
        } else {
            /* Password authentication supported, but not implemented yet */
            return SSHD_AUTH_FAILURE;
        }
    }

    /* ssh_userauth::isDataAvailable
     * Returns true if the service has any data to send to the client.
     */
    bool ssh_userauth::isDataAvailable()
    {
        return false;
    }

    /* ssh_uderauth::read
     * Writes data to the dst
     */
    int ssh_userauth::read(uint8_t * dst, uint32_t size, uint32_t * len)
    {
        ssh::ArrayStream stream( dst, size );
        return ERR_FAILED;
    }

};