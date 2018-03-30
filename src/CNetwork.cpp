/* CNetwork.cpp
 * Implements the network functionality
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* project includes */
#include "CNetwork.h"

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#endif

/* project includes */
#include "errors.h"

namespace ssh
{
    /* CNetwork::CNetwork
     * Performs the required initialization-
     */
    CNetwork::CNetwork()
    {
        m_sock = 0;
        m_addr = NULL;
    }

    /* CNetwork::~CNetwork
     * Performs the required cleanup.
     */
    CNetwork::~CNetwork()
    {
        if( m_sock )
            closesocket( m_sock );
        if( m_addr )
            freeaddrinfo(m_addr);
    }

    /*
     * initializes the socket
     */
    bool CNetwork::init()
    {
        if( !m_sock ) {
            m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if( !m_sock )
                return false;
        }
        return true;
    }

    /* CNetwork::connect
     *
     */
    int CNetwork::connect(const char * host, const char * port)
    {
        int res;
        addrinfo hints;

        if( m_addr )
            freeaddrinfo(m_addr);

        m_sock = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if( !m_sock ) 
            return sshd_ERROR;

        setBlockingMode(false);

        ZeroMemory( &hints, sizeof(hints) );
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if( getaddrinfo(host, port, &hints, &m_addr) != 0 )
            return sshd_HOST_ERROR;

        res = ::connect(m_sock, m_addr->ai_addr, (int)m_addr->ai_addrlen);
        if( res == SOCKET_ERROR )
        {
            if( WSAGetLastError() == WSAEWOULDBLOCK )
                /* connection is pending */
                return sshd_CONNECTION_PENDING;
            else
                return sshd_ERROR;
        } else {
            return sshd_OK;
        }
    }

    /* CNetwork::poll
     *
     */
    int CNetwork::poll(int timeout)
    {
        int res;
        fd_set rd;
        timeval tv = {0, timeout * 1000};
        FD_ZERO(&rd);
        FD_SET(m_sock, &rd);
        res = select(0, 0, &rd, 0, &tv);
        if( res == 1 )
            return sshd_OK;
        else if( res == 0 )
            return sshd_CONNECTION_PENDING;
        else
            return sshd_ERROR;
    }

    /* disconnect 
     * 
     */
    void CNetwork::disconnect()
    {
        if(m_sock) 
            closesocket(m_sock);
        m_sock = 0;
    }

    /* CNetwork::dataAvailable
     * returns true if any data is available for reading.
     */
    bool CNetwork::dataAvailable(int timeout)
    {
        fd_set rd;
        timeval tv = {0, timeout * 1000};
        FD_ZERO(&rd);
        FD_SET(m_sock, &rd);
        return (select(0, &rd, 0, 0, &tv) > 0);
    }

    /* CNetwork::writePossible
     * Check if it's possible to write anything to the output buffer.
     */
    bool CNetwork::writePossible(int timeout)
    {
        fd_set rd;
        timeval tv = {0, timeout * 1000};
        FD_ZERO(&rd);
        FD_SET(m_sock, &rd);
        return (select(0, 0, &rd, 0, &tv) > 0);
    }

    /* CNetwork::readBytes
     * Reads up to count bytes from the socket.
     * 
     * Return values:   0   - Connection closed.
     *                  < 0 - error
     *                  > 0 - success
     */
    int CNetwork::readBytes(
        byte * dst,             /* destination */
        int count,              /* number of bytes to read */
        int * rcount)           /* number of bytes actually read */
    {
        int res;
        if( !dst || count <= 0 ) {
            return sshd_ERROR;
        }
        
        res = recv(m_sock, (char *) dst, count, 0);
        if( res == SOCKET_ERROR ) {
            int error = WSAGetLastError();
            return sshd_ERROR;
        } 
        else if( res == 0 ){
            return sshd_DISCONNECTED;
        } else {
            *rcount = res;
            return sshd_OK;
        }
    }

    /* CNetwork::readBytes
     * Writes up to 'count' bytes from the socket.
     */
    int CNetwork::writeBytes(
        const byte * src,       /* source buffer */
        int count,              /* number of bytes to write */
        int * wcount)               /* number of bytes actually written */
    {
        int res;
        if( !src || count <= 0 ) {
            return sshd_ERROR;
        }
        res = send(m_sock, (const char *) src, count, 0);
        if( res == SOCKET_ERROR ) {

            if( WSAGetLastError() == WSAEWOULDBLOCK ) {
                *wcount = 0;
                return sshd_OK;
            }
            return sshd_ERROR;
        } 
        else {
            *wcount = res;
            return sshd_OK;
        }
    }

    /* CNetwork::listenAndAccept
     * Listens and accepts any incoming connection
     */
    CNetwork * CNetwork::waitForConnections(int timeout, int * status) 
    {
        *status = SSHD_NETWORK_ERROR;
#ifdef WIN32
        if( !m_sock )
            return NULL;

        int res;
        fd_set rd;
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = timeout * 1000;    /* convert timeout to microseconds */

        if( !m_sock )
            return NULL;

        FD_ZERO(&rd);
        FD_SET(m_sock, &rd);
        /* check for any incoming socket */
        res = select(0, &rd, NULL, NULL, &tv);
        if( res == SOCKET_ERROR )
            return NULL;
        else if( res == 0 ) {
            *status = SSHD_NETWORK_OK;
            return NULL;
        } else if( res > 0 ) {
            /* incoming connection */
            SOCKET sock = accept(m_sock, NULL, NULL);
            if( !sock ) {
                return NULL;
            }
            CNetwork * rd = new CNetwork();
            if( !rd ) {
                return NULL;
            }
            rd->m_sock = sock;
            *status = SSHD_NETWORK_OK;
            return rd;
        } else {
            return NULL;
        }
#else
        return NULL;
#endif
    }

    /* CNetwork::bind
     * Binds the socket to a specific port.
     */
    bool CNetwork::bind(uint16_t port)
    {
#ifdef WIN32
        if( !m_sock ) {
            m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if( !m_sock )
                return false;
        }

        struct sockaddr_in saServer;
        hostent* localHost;
        char* localIP;

        localHost = gethostbyname("127.0.0.1");
        localIP = inet_ntoa (*(struct in_addr *)*localHost->h_addr_list);

        saServer.sin_family = AF_INET;
        saServer.sin_addr.s_addr = inet_addr(localIP);
        saServer.sin_port = htons(port);

        if( ::bind( m_sock,(SOCKADDR*) &saServer, sizeof(saServer) ) != 0 ) {
            return false;
        }

        if( ::listen(m_sock, 10) != 0 )
            return false;

        return true;
#else
        return false;
#endif
    }

    /* CNetwork::setBlockingMode
     *
     */
    CNetwork & CNetwork::setBlockingMode(bool block)
    {
        u_long iMode = (block ? 0 : 1);
        ioctlsocket(m_sock,FIONBIO,&iMode);
        return (*this);
    }

    /* CNetwork::writeLine
     * Writes a raw line to the socket.
     */
    bool CNetwork::writeLine(const std::string & line)
    {
        int res, wcount;
        char * buf = NULL;
        uint32_t offset = 0;
        size_t count = line.size();
    
        if (!(buf = new char[count + 2]))
            return false;

        memcpy(buf, line.c_str(), count);
        buf[count] = 0x0D;
        buf[count+1] = 0x0A;

        count += 2;

        while( offset < count )
        {
            res = writeBytes((const byte *) (buf + offset), (int) (count - offset), &wcount);
            if( res == sshd_OK ) {
                offset += wcount;
            }
            else {
                delete buf;
                return false;
            }
        }

        delete [] buf;
        return true;
    }

    /* CNetwork::readLine
     * Reads a CR LF terminated line from the socket.
     */
    bool CNetwork::readLine(std::string & line)
    {
        char buf[1025]; /* allow for 1024 chars + linefeed */
        int i = 0, res, state = 1, rcount;
        char c;

        while( i < 1024 )
        {
            /* read a single char from the socket */
            res = readBytes((byte *)&c, 1, &rcount);
            if( res == sshd_OK && rcount == 1 ) {
                if( c == 0 || c > 127 ) /* illegal character */
                    return false;

                switch( state )
                {
                case 1:
                    if( c == 0x0D ) { /* read a carriage return */
                        state = 2;
                    } else if( c == 0x0A ) { /* read a linefeed without a carriage return first */
                        return false;
                    } else {
                        buf[i++] = c;
                    }
                    break;
                case 2:
                    /* have read a carriage return before */
                    if( c == 0x0A ) {
                        /* read a line feed , string complete */
                        buf[i] = NULL;
                        line = buf;
                        return true;
                    } else {
                        return false;
                    }
                    break;
                default:
                    return false;
                }
            } else {
                return false;
            }
        }
        return false;
    }
};