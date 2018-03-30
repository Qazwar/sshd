/* services.cpp
 * Implements generic server side functions for dealing with services.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

#include "CServerTransport.h"
#include <list>

using namespace std;

namespace ssh
{
    /* registerAuthenticationService 
     * A authentication service is register with a supplied factory method which is called by
     * the server to create the instances.
     */
    bool CServerTransport::registerAuthenticationService(const std::string & name, ssh::AuthenticationFactory method, void * userData)
    {
        if( !method )
            return false;

        list<pair<string, ssh::AuthenticationFactory> >::iterator it;
        for( it = m_authServices.begin(); it != m_authServices.end(); it++) {
            if( it->first == name )
                return false;
        }
        /* add the method to the list */
        m_authServices.push_back(pair<string, ssh::AuthenticationFactory>(name, method));

        return true;
    }

    /* registerService
     * Registers a service to be available to the SSH server.
     */
    bool CServerTransport::registerService(const std::string & name, ssh::ServiceFactory method, void *)
    {
        if( !method )
            return false;

        list<pair<string, ssh::ServiceFactory> >::iterator it;
        for( it = m_services.begin(); it != m_services.end(); it++) {
            if( it->first == name )
                return false;
        }
        /* add the method to the list */
        m_services.push_back(pair<string, ssh::ServiceFactory>(name, method));

        return true;
    }

    /* CServerTransport::createAuthenticationService
     * Creates a authentication service matching the supplied name.
     */
    CAuthenticationService * CServerTransport::createAuthenticationService(const std::string & name, CTransport * transport)
    {
        list<pair<string, ssh::AuthenticationFactory> >::iterator it;
        for( it = m_authServices.begin(); it != m_authServices.end(); it++) {
            if( it->first == name ) {
                /* found the entry with the matching name */
                return it->second( name, transport, NULL ); /* TODO, replace with userdata */
            }   
        }
        return NULL;
    }

    /* CServerTransport::createService
     *
     */
    CService * CServerTransport::createService( const std::string & name )
    {
        list<pair<string, ssh::ServiceFactory> >::iterator it;
        for( it = m_services.begin(); it != m_services.end(); it++) {
            if( it->first == name ) {
                /* found a etry with a matching name */
                return it->second( name, NULL); /* TODO, replace with userdata */
            }
        }
        return NULL;
    }
};