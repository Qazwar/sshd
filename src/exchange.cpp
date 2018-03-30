/* project specific includes */
#include "CTransport.h"
#include "sshd.h"
#include "messages.h"
#include "debug.h"
#include "errors.h"

using namespace std;

namespace ssh
{
    /* CTransport::exchangeProtocolVersions
     * Exchanges the protocol version strings.
     */
    int CTransport::exchangeProtocolVersions()
    {
        ProtocolVersion remoteVersion;
    
        /* construct the local protocol string */
        buildLocalVersionString();

        /* first write the local protocol string */
        if( !ds->writeLine(m_localVersion) ) {
            sshd_Log(sshd_FATAL_ERROR, "Failed to write local protocol version.");
            return sshd_ERROR;
        }

        /* The client MUST only send the protocol version string
           to the server.
         */
        if( isServer() ) {
            if( !ds->readLine(m_remoteVersion) ) {
                sshd_Log(sshd_FATAL_ERROR, "Failed to read remote protocol version.");
                return sshd_ERROR;
            }
        } 
        else {
            /* The server MAY send additional messages before the protocol 
               version string, so the client must correctly handle this
             */
            string line;
            int count = 0, limitValue;

            if( !m_settings.GetValue(SSHD_SETTING_MAX_MOTD_COMMENTS, limitValue) )
                limitValue = 250;
            
            while( 1 )
            {
                /* read a single line */
                if( !ds->readLine(line) ) {
                    sshd_Log(sshd_FATAL_ERROR, "Failed to read line.");
                    return sshd_ERROR;
                }

                if( line.find("SSH-") != 0 )
                {
                } else {
                    m_remoteVersion = line;
                    break;
                }

                if( (++count) > limitValue ) {/* prevent the server from spamming us */
                    sshd_Log(sshd_FATAL_ERROR, "Server is spamming us!.");
                    return sshd_ERROR;      
                }
            }
        }

        /* now parse the remote protocol version */
        if( !parseProtocolVersion(m_remoteVersion, &remoteVersion) )
        {
            sshd_Log(sshd_FATAL_ERROR, "Failed to parse protocol string.");
            return sshd_ERROR;
        }

        /* now verify that the protocol version is supported */
        if( remoteVersion.protocolVersion != "2.0" &&
            remoteVersion.protocolVersion != "1.99" ) 
        {
            return sshd_PROTOCOL_VERSION_UNSUPPORTED;
        }

        return sshd_OK;
    }

    /* CTransport::parseProtocolVersion
     * Parses the protocol version string and extracts the version information.
     */
    bool CTransport::parseProtocolVersion(const string & str, ProtocolVersion * pv) const
    {
        size_t protoEnd, protoPos, softEnd;

        /* SSH-protoversion-softwareversion SP comments */
        protoPos = str.find_first_of('-');  /* find the '-'beforce the protocol version */
        if( protoPos != 3 )
            return false;

        if( str.length() <= protoPos + 1 ) {    /* verify boundry */
            return false;
        }
        /* find the end of the protocol version string */
        protoEnd = str.find_first_of('-', protoPos + 1);
        pv->protocolVersion = str.substr(protoPos + 1, protoEnd - protoPos - 1);

        if( protoEnd == string::npos || (str.length() <= (protoEnd + 1)) )
            return false;

        /* the software version is after the protocol version */
        softEnd = str.find_first_of(' ', protoEnd + 1);
        pv->softwareVersion = str.substr(protoEnd+1, (softEnd - protoEnd+1));
        
        if( softEnd != string::npos ) { /* comment included */ 
            pv->comment = str.substr( softEnd + 1 );
        }
        return true;
    }

    /* CTransport::exchangeKeyExchanges
     * Exchanges the keyexchange packets. This function both handles the initial keyexchange proces 
     * and the two different cases which may occur when the connection has been established
     */
    int CTransport::exchangeKeyExchanges(const KeyExchangeInfo & local,
            KeyExchangeInfo & remote,
            bool bInitiator,
            bool bInitial)
    {
        int res;
        uint8_t type;

        newPacket();
        /* write the local keyexchange information */
        if( !writeKex(local) ) {
            return sshd_ERROR;
        }
        if( bInitial ) {
            /*
             * Initial keyexchange
             */
            res = exchangeAndExpect(SSH_MSG_KEXINIT);
            if( !readKex( remote ) )
                return sshd_PROTOCOL_ERROR;
        } else {
            /*
             * Not the first keyexchange.
             */
            if( bInitiator ) {
                /*  local side is the initiator , send the packet and wait until
                    the remote side respons with a SSH_MSG_KEXINIT message */
                res = sendPacket(4000);
                if( res != sshd_OK )
                    return sshd_ERROR;

                /* maybe we should have a upper limit on how long we will wait? */
                while( 1 ) {

                    sshd_CheckAbortEvent()
                    res = readPacketNonblock(100);
                    if( res == sshd_OK )
                    {
                        /* a packet has been read */
                        getPacketType( type );
                        if( type == SSH_MSG_KEXINIT ) {
                            /* parse the SSH_MSG_KEXINIT message */
                            if( !readKex( remote ) )
                                return sshd_PROTOCOL_ERROR;
                            break;
                        }
                        /* handle packets */
                        res = handlePacket();
                        if( res != sshd_OK )
                            return res;
                    } 
                    else if( res != sshd_PACKET_PENDING || res != sshd_NO_PACKET )
                    {
                        /* Error */
                        return res;
                    }
                }
            } else {
                /* the local side is not the initiator and the remote kex should already be 
                   read before calling this function */
            }
        }
    
        /* */
        m_localKex.packetSize   = sendState.hdr.packetSize;
        m_localKex.paddingSize  = sendState.hdr.padding;
        m_remoteKex.packetSize  = readState.hdr.packetSize;
        m_remoteKex.paddingSize = readState.hdr.padding;

        return sshd_OK;
    }

    /* CTransport::exchangeAndExpect
     * Sends the current packet in the output buffer and waits a for a reply 
     */
    int CTransport::exchangeAndExpect(byte id)
    {
        int res;
        byte msg;

        res = sendPacket();
        if( res != sshd_OK )
            return sshd_ERROR;

        res = readPacket();
        if( res != sshd_OK )
            return sshd_ERROR;

        getPacketType( msg );
        if( msg != id )
            return sshd_ERROR;

        return sshd_OK;
    }
};