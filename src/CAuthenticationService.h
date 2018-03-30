/* CAuthenticationService.h
 * Baseclass for the authentication services.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

#ifndef _CAUTHENTICATIONSERVICE_H_
#define _CAUTHENTICATIONSERVICE_H_

#include "CService.h"

enum {
    SSHD_AUTH_OK = 0,                       /* authentication success */
    SSHD_AUTH_ERROR,
    SSHD_AUTH_SUCCESS,
    SSHD_AUTH_FAILURE,                      /* authentication failure */
    SSHD_AUTH_METHOD_NOT_ALLOWED,
};

namespace ssh
{
    /* CAuthenticationService
     * Baseclass for the authentication services.
     */
    class CAuthenticationService : public CService
    {
    public:
        virtual void OnSuccess() {}
    };
};

#endif