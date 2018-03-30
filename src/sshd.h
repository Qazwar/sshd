#ifndef _SSHD_H_
#define _SSHD_H_

/* project include */
#include "MessageQueue.h"
#include "CNetwork.h"
#include "CTransport.h"
#include "CServerTransport.h"
#include "types.h"
#include "CSettings.h"
#include "errors.h"
#include "CThread.h"

/*****************************************************************************/
/*                              DEFINITIONS                                  */
/*****************************************************************************/


#define sshd_CheckAbortEvent()          if (m_abortEvent.isSignaled()) return sshd_CONNECTION_ABORTED;
#define sshd_CheckAbortEvent_NoRet()    (m_abortEvent.isSignaled())
#define sshd_Log(event, message) do{fprintf(stderr, message "\r\n");} while(0)

namespace ssh
{
    typedef enum
    {
        sshd_EVENT_WARNING = 0,     /* warning *
        sshd_EVENT_FATAL,           /* fatal error */
        sshd_EVENT_NOTIFY           /* general notification */
    } LogEvents;

    /* sshd
     * Secure Shell Server Deamon
     */
    class sshd : public Util::CThread
    {
    public:
        bool init(const char * name);
        void Task();
        /* initiate server shutdown */
        void shutdown();

        /* registers a authentication service with the server */
        int registerAuthService( ssh::AuthenticationFactory , const std::string & name, void * );
        int registerService( ssh::ServiceFactory, const std::string & name, void * );
            
        /* creates a instance of a registered authentication service */
        int sshd::createAuthService( const std::string & serviceName, CTransport *, CAuthenticationService ** ) const;
        int sshd::createService( const std::string & serviceName, CService ** ) const;

    protected:
    
        void performShutdown();

        typedef struct {
            ssh::AuthenticationFactory  factory;
            std::string                 name;
            void *                      user;
        } reg_auth_service;

        typedef struct {
            ssh::ServiceFactory         factory;
            std::string                 name;
            void *                      user;
        } reg_service;

        /* */
        std::list< reg_auth_service >   m_regAuthServices;  /* the registered authenication services */
        std::list< reg_service >        m_regServices;      /* the registered services */

        /* server settings */
        CSettings m_settings;
        std::list<ssh::CServerTransport *> m_clients;
    };
};

#endif