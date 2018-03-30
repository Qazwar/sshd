/* C/C++ standard includes */
#include <cstdlib>
#include <sstream>

/* project specific includes */
#include "CTransport.h"
#include "sshd.h"
#include "CAlgorithm.h"
#include "messages.h"
#include "errors.h"

#include <boost\shared_ptr.hpp>
#include <openssl/rand.h>

using namespace std;

namespace ssh
{
    /*
     * Default algorithms
     */
    const char * defaultKeyexchange     = "diffie-hellman-group14-sha1";
    const char * defaultHostkey         = "ssh-rsa, ssh-dss";
    const char * defaultCiphers         = "aes256-cbc,aes128-cbc";
    const char * defaultHmacs           = "hmac-sha1";

    /* CTransport::CTransport
     * Performs the required initialization.
     */
    CTransport::CTransport(const ssh::CSettings & settings, ssh::CNetwork * network) 
        : m_settings(settings), ds( network )
    {
        memset(&readState, 0, sizeof(readState));
        memset(&sendState, 0, sizeof(sendState));

        /* set initial packet state */
        readState.state = sshd_STATE_NO_PACKET;
        sendState.state = sshd_STATE_NO_PACKET;
    }

    /* CTransport::~CTransport
     * Perform the required cleanup
     */
    CTransport::~CTransport()
    {
#ifdef WIN32
        if( readState.pData ) {
            VirtualFree(readState.pData, readState.bufSize, MEM_RELEASE);
            readState.pData = NULL;
        }

        if( sendState.pData ) {
            VirtualFree(sendState.pData, sendState.bufSize, MEM_RELEASE);
            sendState.pData = NULL;
        }

#else
        if( readState.pData ) {
            delete [] readState.pData;
            readState.pData = NULL;
        }

        if( sendState.pData ) {
            delete [] sendState.pData;
            sendState.pData = NULL;
        }
#endif
        if( ds ) {
            delete ds;
            ds = 0;
        }
    }

    /* CTransport::init
     *
     */
    bool CTransport::init()
    {
        uint32_t size = 1024 * 36;

        sendState.bufSize = size;
        readState.bufSize = size;

#ifdef WIN32
        /* allocate the memory and disable code execution from them. */
        readState.pData = (uint8_t *) VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if( !readState.pData ) {
            goto cleanup;
        }
        sendState.pData = (uint8_t *) VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
        if( !sendState.pData ) {
            goto cleanup;
        }

#else
        /* C++ implementation */
        readState.pData = new unsigned char[size];
        if( !readState.pData )
            goto cleanup;

        sendState.pData = new unsigned char[size];
        if( !readState.pData )
            goto cleanup;
#endif

        sendState.pPayload = sendState.pData + sizeof(ssh_hdr);
        readState.pPayload = readState.pData + sizeof(ssh_hdr);

        /* return success */
        return true;
cleanup:

#ifdef WIN32
        if( readState.pData ) {
            VirtualFree(readState.pData, size, MEM_RELEASE);
            readState.pData = NULL;
        }

        if( sendState.pData ) {
            VirtualFree(sendState.pData, size, MEM_RELEASE);
            sendState.pData = NULL;
        }
#else
        if( readState.pData ) {
            delete [] readState.pData;
            readState.pData = NULL;
        }

        if( sendState.pData ) {
            delete [] sendState.pData;
            sendState.pData = NULL;
        }
#endif
        return false;
    }

    /* CTransport::disconnect
     * Writes a disconnect message and the closes the socket
     */
    void CTransport::disconnect(uint32_t reason, const char * str)
    {
        int res;
        /* first try to flush any outgoing packet */
        res = flushPacket( 250 );
        if( res != sshd_OK ) 
        {
            ds->disconnect();       /* just disconnect */
        } 
        else
        {
            newPacket();
            /* write packet payload */
            if( !writeByte(SSH_MSG_DISCONNECT) ||               /* message type */
                !writeInt32( reason ) ||                        /* reason for disconnect */
                (str ? writeString(str) : writeInt32(0)) ||     /* string describing the reson */
                !writeInt32(0) )                                /* language tag */
            {
                ds->disconnect();
                return;
            }
            /* write the packet */
            sendPacket( 250 );
            /* disocnnect regardless of the result of the previous operation */
            ds->disconnect();
        }
    }

    /* CTransport::buildLocalVersionString
     *
     */
    bool CTransport::buildLocalVersionString()
    {
        std::stringstream ss;
        string name, version;

        /* get the software name */
        if( !m_settings.GetString(SSHD_SETTING_SOFTWARE_NAME, name) ) {
            name = "lwSSH";
        }
        /* get the software version as a string */
        if( !m_settings.GetString(SSHD_SETTING_SOFTWARE_VERSION, version) ) {
            version = "0.01";
        }
        ss << "SSH-2.0-" << name << "_" << version;

        m_localVersion = ss.str();
        return true;
    }

    /* CTransport::buildLocalKex
     * Constructs the local Keyexchange information based on the settings. 
     */
    bool CTransport::buildLocalKex()
    {
        std::string keyexchange, hostkey, ciphers, hmac;

        if( !m_settings.GetString( SSHD_SETTING_PREFERRED_KEYEXCHANGE, keyexchange) )
            keyexchange = defaultKeyexchange;
        if( !m_settings.GetString(SSHD_SETTING_PREFERRED_HOSTKEY, hostkey) )
            hostkey = defaultHostkey;
        if( !m_settings.GetString(SSHD_SETTING_PREFERRED_CIPHER, ciphers) )
            ciphers = defaultCiphers;
        if( !m_settings.GetString(SSHD_SETTING_PREFERRED_HMAC, hmac) )
            hmac = defaultHmacs;

        /* store algorithms */
        m_localKex.algorithms[KEYEXCHANGE_METHOD]           = keyexchange;
        m_localKex.algorithms[SERVER_HOSTKEY]               = hostkey;
        m_localKex.algorithms[ENCRYPTION_CLIENT_TO_SERVER]  = ciphers;
        m_localKex.algorithms[ENCRYPTION_SERVER_TO_CLIENT]  = ciphers;
        m_localKex.algorithms[MAC_CLIENT_TO_SERVER]         = hmac;
        m_localKex.algorithms[MAC_SERVER_TO_CLIENT]         = hmac;
        m_localKex.algorithms[COMPRESSION_CLIENT_TO_SERVER] = "none";
        m_localKex.algorithms[COMPRESSION_SERVER_TO_CLIENT] = "none";

        /* randomize the cookie */
        randomizeData( m_localKex.cookie, 16 );
        m_localKex.follows = 0;

        return true;
    }
    
    /* CTransport::randomizeData
     * Fills the supplied buffer with pseudo random numbers.
     */
    void CTransport::randomizeData(uint8_t * dst, uint32_t len)
    {
#if 0
        for(uint32_t i = 0; i < len; i++) {
            dst[i] = rand() % 255;
        }
#else
        RAND_pseudo_bytes(dst, (int)len);
#endif
    }

    /* CTransport::isTransportMessage
     *
     */
    bool CTransport::isTransportPacket()
    {
        byte type;
        getPacketType( type );
        
        switch( type )
        {
        case SSH_MSG_DISCONNECT:
        case SSH_MSG_IGNORE:
        case SSH_MSG_UNIMPLEMENTED:
        case SSH_MSG_DEBUG:
        case SSH_MSG_SERVICE_REQUEST:
        case SSH_MSG_SERVICE_ACCEPT:
        case SSH_MSG_KEXINIT:
        case SSH_MSG_NEWKEYS:
            return true;
        default:
            return false;
        }
    }
};