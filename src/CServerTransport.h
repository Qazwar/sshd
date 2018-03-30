/* CServerTransport.h
 * Defines the Server side transport layer
 *
 * Copyright © 2006-2009 Magnus Leksell, all rights reserved.
 */
#ifndef _CSERVERTRANSPORT_H_
#define _CSERVERTRANSPORT_H_

/* standard includes */
#include <list>
#include <string>
#include <utility>

/* project includes */
#include "CTransport.h"
//#include "CService.h"
#include "CAuthenticationService.h"
#include "CNetwork.h"
#include "CThread.h"

/* server states */
typedef enum {
    sshd_AUTH_STATE_WAIT_SERVICE_REQUEST = 0,
    sshd_AUTH_STATE_SERVICE_ACCEPT
} sshd_AuthState;

namespace ssh
{
    /* declarations */
    class sshd;

    typedef ssh::CAuthenticationService * (* AuthenticationFactory) (const std::string &, CTransport *, void *);
    typedef ssh::CService * (* ServiceFactory) (const std::string &, void *);

    /* sshd::CServerTransport
     * Implements the server specific parts of the transport layer
     */
    class CServerTransport : public CTransport
    {
    public:
        CServerTransport(const CSettings &, ssh::CNetwork *, ssh::sshd *);
        ~CServerTransport();

        /*
         * Registers a SSH service.
         * Two services are defined in the SSH protocol, ssh-userauth and ssh-connection.
         * Any new non-standard services should be defined on the following format name@domain.
         */
        bool registerAuthenticationService(const std::string &, ssh::AuthenticationFactory, void *);
        /* registerService
         * Registers a service to be available to the SSH server, only clients may request services.
         */
        bool registerService(const std::string &, ssh::ServiceFactory, void *);

        /* establishes the connection */
        int establishConnection();
        /* performs a keyexchange */
        int performKeyExchange(bool bInitial = true, bool bInitiator = true);
    
        bool isServer() {return true;}

        int displayMotd(const char * filename);
        int displayMotd(const std::string &);

        const KeyExchangeInfo & getServerKex() {return m_localKex;}
        const KeyExchangeInfo & getClientKex() {return m_remoteKex;}
        const std::string & getServerProtocolString() {return m_localVersion;}
        const std::string & getClientProtocolString() {return m_remoteVersion;}

    protected:

        void Task();
        void mainTask();

        /* authentication */
        int performAuthentication();
        int handleAuthPacket();
        int tryHandleAuthServiceRequest();
        
        int handlePacket();

        virtual void InitializeKeys(const SecurityBlock & block, const KeyVector & vec);
        virtual int TakeAlgorithmsInUse( const SecurityBlock & block );


        CAuthenticationService *    createAuthenticationService(const std::string & name, ssh::CTransport *);
        CService *                  createService( const std::string & name );

        /* The registered authentication services */
        std::list<std::pair<std::string, ssh::AuthenticationFactory> > m_authServices;
        /* The registered services */
        std::list<std::pair<std::string, ssh::ServiceFactory> > m_services;

        /* User authentication */
        CAuthenticationService *    m_pAuthService;
        sshd_AuthState              m_authState;

        /* service */
        ssh::CService *             m_pService;

        /* the SSH server */
        ssh::sshd *                 m_sshd;
    };
};

#endif