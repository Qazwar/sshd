/* CClientTransport.h
 * Implements the client side of the SSH transport protocol
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

#ifndef _CCLIENTTRANSPORT_H_
#define _CCLIENTTRANSPORT_H_

/* C/C++ includes */
#include "CTransport.h"
#include "reasons.h"
#include "MessageQueue.h"
#include "CService.h"
#include "CAuthenticationService.h"
#include "CThread.h"
#include "IAuthenticate.h"
#include "INotify.h"

typedef enum {
    sshd_STATUS_IDLE = 0,       /* idle state */
    sshd_STATUS_CONNECTING,     /* connecting to server */
    sshd_STATUS_CONNECTED,      /* connected to status */
    sshd_STATUS_FAILURE,
    sshd_STATUS_CLOSED
} sshd_ConnectStatus;

namespace ssh
{
    /* CClientTransport
     * Implements the client side of the SSH transport protocol.
     */
    class CClientTransport : public CTransport
    {
    public:
        CClientTransport(const ssh::CSettings & settings, ssh::INotify *, ssh::IAuthenticate *);
        virtual ~CClientTransport();

        bool isServer() {return false;}

        /* connects to the remote server */
        int connect(const char *, const char * port);
        int connect(const std::string &, const std::string &);

        /* */
        virtual const KeyExchangeInfo & getServerKex()  {return m_remoteKex;}
        virtual const KeyExchangeInfo & getClientKex()  {return m_localKex;}
        virtual const std::string & getServerProtocolString() {return m_remoteVersion;}
        virtual const std::string & getClientProtocolString() {return m_localVersion;}

        /* CThread */
        void Task();
        /* returns the status of the connection */
        sshd_ConnectStatus getStatus();

    protected:

        void setStatus(sshd_ConnectStatus);     /* sets the connection state */
        int establishConnection();
        void mainTask();
        int performKeyExchange(bool bInitial = true, bool bInitiator = true);
        int handlePacket();
        int requestService(const std::string & name);
        int handleAuthPacket();
        int handleTransportPacket();
    
        int performAuthentication(); /* performs the client authentication */

        int TakeAlgorithmsInUse( const SecurityBlock & block );
        void InitializeKeys(const SecurityBlock & block, const KeyVector & vec);

        /* variables */
        std::string                     m_addr;         /* host to connect to */
        std::string                     m_port;         /* port number to use */

        ssh::CService *                 m_pService;     /* service */
        ssh::IAuthenticate *            m_iAuth;        /* authentication service */
        ssh::INotify *                  m_pNotify;      /* notification interface */
        sshd_ConnectStatus              m_status;       /* connection status */
        Util::Mutex                     m_lock;
    };
};

#endif