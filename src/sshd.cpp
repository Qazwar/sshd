/* sshd.cpp
 * Implements a SSH deamon
 *
 * Copyright © 2008-2009 Magnus Leksell, all rights reserved.
 */

#include "sshd.h"
#include <boost\shared_ptr.hpp>
#include "errors.h"
#include <list>

using namespace std;

namespace ssh
{
    /* sshd::init
     * Initializes the SSH deamon.
     */
    bool sshd::init(const char * name)
    {
        if( name )
        {
            /* load the settings from the file */
            if( !m_settings.load( name ) )
                return false;
        }
        
        /* store key-pair */
        m_settings.StoreString(SSHD_SETTING_RSA_PUBLIC_KEY_FILE, "e:\\public.rsa");
        m_settings.StoreString(SSHD_SETTING_RSA_PRIVATE_KEY_FILE, "e:\\private.rsa");

        return true;
    }

    /* sshd::run
     *
     */
    void sshd::Task()
    {
        /*
         * These should be done in the calling thread instead ? 
         */
        unsigned int port = 1337;
        int status;

        ssh::CNetwork net;
        if( !net.init() ) {
            return;
        }

        /* don't block */
        net.setBlockingMode(false);

        /* listen to port */
        if( !net.bind( port ) ) {
            return;
        }

        /* loop until shutdown */
        while( !m_abortEvent.isSignaled() )
        {
            CNetwork * con = net.waitForConnections(250, &status);
            if( status == SSHD_NETWORK_OK )
            {
                if( con )
                {
                    /* incoming connection */
                    CServerTransport * transport = new CServerTransport( m_settings, con, this );
                    transport->init();

                    m_clients.push_back( transport );
                    /* run the transport in a new thread */
                    if( !transport->spawn() ) {
                        /* failed to spawn thread */
                    }
                }
            } else {
                /*
                 * Handle problem.
                 */
            }
        }
        /* shutdown event, perform the required cleanup */
        performShutdown();
    }

    /* sshd::performShutdown
     *
     */
    void sshd::performShutdown()
    {
        /* initiate shutdown for each client. */
        for(list<CServerTransport *>::iterator it = m_clients.begin(); it != m_clients.end(); it++) {
            (*it)->shutdown();
        }
        /* wait for all connections to be closed */
        for(list<CServerTransport *>::iterator it = m_clients.begin(); it != m_clients.end(); it++)
        {
            (*it)->wait();
        }
    }

    /* sshd::registerAuthService
     * Registers a authentication service with the server.
     */
    int sshd::registerAuthService(ssh::AuthenticationFactory factory, const std::string & name, void * user)
    {
        sshd::reg_auth_service item = {factory, name, user};
        m_regAuthServices.push_back( item );
        return sshd_OK;
    }

    /* sshd::registerService
     * Registers a service with the server.
     */
    int sshd::registerService(ssh::ServiceFactory factory , const std::string &name, void * user)
    {
        sshd::reg_service item = {factory, name, user};
        m_regServices.push_back( item );
        return sshd_OK;
    }


    /* sshd::createAuthService
     * Creates a authentication service based on the supplied name.
     */
    int sshd::createAuthService(const std::string & serviceName, CTransport * transport, CAuthenticationService ** ppService) const
    {
        for(list<sshd::reg_auth_service>::const_iterator it = m_regAuthServices.begin();
            it != m_regAuthServices.end();
            it++)
        {
            if( it->name == serviceName ) { /* found a matching service */
                CAuthenticationService * service = it->factory( serviceName, transport, it->user );
                if( !service ) {
                    sshd_Log(sshd_EVENT_FATAL, "Failed to create SSHD authentication service.");
                    return sshd_ERROR;
                }
                *ppService = service;
                return sshd_OK;
            }
        }
        sshd_Log(sshd_EVENT_FATAL, "No such service.");
        return sshd_NO_SUCH_SERVICE;
    }

    /* sshd::createService
     * Creates a SSH service based on the name.
     */
    int sshd::createService(const std::string & serviceName, CService ** ppService) const
    {
        for(list<sshd::reg_service>::const_iterator it = m_regServices.begin();
            it != m_regServices.end();
            it++)
        {
            if( it->name == serviceName ) { /* found a matching service */
                CService * service = it->factory( serviceName, it->user );
                if( !service ) {
                    return sshd_ERROR;
                }
                *ppService = service;
                return sshd_OK;
            }
        }
        return sshd_NO_SUCH_SERVICE;
    }

};