#ifndef _CNETWORK_H_
#define _CNETWORK_H_

/* windows specifc headers */
#if defined(WIN32) || defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

/* project specific headers */
#include "types.h"
#include "CComponent.h"

enum {
    SSHD_NETWORK_OK = 0,                /* success */
    SSHD_NETWORK_ERROR,                 /* general error */
    SSHD_NETWORK_WOULD_BLOCK,           /* the operation would block */
    SSHD_NETWORK_CONNECTION_CLOSED,     /* the connection is closed */
    SSHD_NETWORK_CONNECTION_PENDING     /* the connect attempt is pending */
};

namespace ssh
{
    /* sshd::CNetwork
     * The networking component
     */
    class CNetwork
    {
    public:
        
        CNetwork();
        ~CNetwork();

        /* initializes the socket */
        bool init();
        void disconnect();

        bool dataAvailable(int);                    /* returns true if data is available for reading */
        bool writePossible(int);

        int readBytes(byte *, int, int *);              /* read data from the socket */
        int writeBytes(const byte *, int, int *);       /* writes data to the socket */
    
        bool writeLine(const std::string &);    /* writes a raw CR LF terminated line to the socket */
        bool readLine(std::string &);           /* reads a raw CR LFT terminated line from the socket */

        /* binds the socket to a specific port */
        bool bind(uint16_t);
        /* connects to a remote host */
        int connect(const char *, const char * port);
        /* polls the interface for connection status */
        int poll(int);

        /* sets blocking/non-blocking mode */
        CNetwork & setBlockingMode(bool block = true);
        
        /* listens to any incoming connection */
        CNetwork * waitForConnections(int timeout, int * status);

    protected:
#ifdef WIN32
        SOCKET m_sock;
        addrinfo * m_addr;
#endif
    };
};

#endif