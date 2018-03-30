#ifndef _IAUTHENTICATE_H_
#define _IAUTHENTICATE_H_

#include <types.h>
#include <string>

namespace ssh
{
    /* IAuthenticate
     *
     */
    class IAuthenticate
    {
    public:
        /* returns the name of the authentication service */
        virtual std::string getAuthServiceName() = 0;
        /* called if the authentication is successfull */
        virtual void onAuthSuccess() {}
        /* called if the authentication fails */
        virtual void onAuthFailure() {}
        /* reads a packet from the authentication service */
        virtual int authReadPacket(byte *, size_t, size_t *) = 0;
        /* writes data to the authentication service */
        virtual int authWritePacket(byte *, size_t) = 0;
        /* */
        virtual void onAuthBanner() {}
        /* */
        virtual bool authIsDataAvailable() = 0;
    };
}

#endif