#ifndef _ERRORS_H_
#define _ERRORS_H_

typedef enum 
{
    sshd_OK = 0,
    sshd_ERROR,             /* generic error */
    sshd_PACKET_PENDING,
    sshd_NO_PACKET,
    sshd_PROTOCOL_ERROR,
    sshd_INTERNAL_ERROR,
    sshd_CONNECTION_PENDING,
    sshd_PROTOCOL_VERSION_UNSUPPORTED,
    sshd_HOST_ERROR,
    sshd_CONNECTION_ABORTED,
    sshd_DISCONNECTED,
    sshd_CLIENT_AUTHENTICATED,
    sshd_CLIENT_NOT_ALLOWED,
    sshd_NO_SUCH_SERVICE,

};

#endif