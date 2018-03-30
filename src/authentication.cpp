/* authentication.cpp
 * 
 * Copyright (c) 2006-2009 Magnus Leksell 
 */

#include "CServerTransport.h"
#include "messages.h"

#include <string>

using namespace std;

namespace ssh
{
    /* CServerTransport::performAuthentication
     *
     */
    int CServerTransport::performAuthentication()
    {
        int type;

        while (1)
        {
            switch( type )
            {
            case SSH_MSG_DISCONNECT:
                /* connection closed by remote side */
                break;
            case SSH_MSG_IGNORE:
                break;
            case SSH_MSG_USERAUTH_REQUEST:
                {
                    wstring user;
                    string service, method;

                //  if( /*!readStringUTF8(user) ||*/ !readString(service) || !readString(method) ) {
                //      /* failed to read packet */
                //  }
                //  if( !validUser( user ) ) { /* not a valid user */
                //  }

                //  if( !validService( service) ) { /* not a valid service */
                //  }

                //  if( handleAuthentication(user, service, method, &methods) != OK ) {
                //      
                //      if( ++attempts >= MAX_AUTH_ATTEMPTS ) {
                //          /* to many attempts */
                //          disconnect("Too many authentication attempts.");
                //          return ERR_CLOSED;
                //      } else {
                //          /* Authentication failure */
                //          writeByte( SSH_MSG_USERAUTH_FAILURE );
                //          writeString( methods );
                //          writeByte( 0 );
                //      }
                //  } else {
                //      /* authenticated */
                //      writeByte( SSH_MSG_USERAUTH_SUCCESS );
                //  }
                //}
                }
                break;

            default:
                /* disconnect if the server sends anything else */
                break;
            }
        }
    }
};