#ifndef _SSH_USERAUTH_H_
#define _SSH_USERAUTH_H_

#include <string>

/* project includes */
#include "CAuthenticationService.h"
#include "CStream.h"
#include "UserInfo.h"

#define MAX_AUTHENTICATON_ATTEMPTS (20)

/* Authentication methods */
enum
{
    SSHD_AUTH_METHOD_NONE = 0,
    SSHD_AUTH_METHOD_PASSWORD,
    SSHD_AUTH_METHOD_PK
};

/* states */
enum
{
    SSH_USERAUTH_STATE_INIT
};


namespace ssh
{
    /* ssh_userauth
     * Implements the ssh-userauth authentication protocol.
     */
    class ssh_userauth : public CAuthenticationService
    {
    public:
        bool init(const CSettings &);
        /* reads data from the service */
        int read(uint8_t * dst, uint32_t size, uint32_t * len);
        /* returns true if the service has anything to send */
        bool isDataAvailable();
        /* handles authentication messages */
        int handleAuthentication(const uint8_t * src, uint32_t size);

    protected:
        void flushState();

        /* */
        int performAuthentication(CStream & stream, 
                                    const std::string & method, 
                                    const std::wstring & username, 
                                    const UserInfo & info);
        /* */
        int doNoneAuthentication( CStream & stream, 
                                    const std::wstring & userName, 
                                    const UserInfo & info );

        int doPasswordAuthentication( CStream & stream,
                                                const std::wstring & username,
                                                const UserInfo & info );

    private:

        std::wstring                orgUserName;
        std::string                 orgService;
        bool                        m_initialAttempt, m_bogusAuth;
        UserInfo                    m_info;
        uint32_t                    m_authState;
        int                         m_numAttempts, m_state, m_maxAuthAttempts;
        uint32_t                    m_settings;
    };
};

#endif