/* keyexchange.cpp
 * Handles the keyexchange process.
 *
 * Copyright (c) 2006-2009 Magnus Leksell, all rights reserved.
 */

/* C/C++ includes */
#include <memory>   /* for auto_ptr */
#include <vector>
#include <string>

/* project includes */
#include "CTransport.h"
#include "debug.h"
#include "sshd.h"
#include "CKeyExchange.h"
#include "util.h"

using namespace std;

namespace ssh
{
    /* CTransport::DecideAlgorithms
     * Decides what algorithms to use.
     */
    bool CTransport::DecideAlgorithms
        (
        const std::string client[],     /* The client algorithms */
        const std::string server[],     /* The server algorithms */
        std::string match[],
        int count
        ) const
    {
        for(int i = 0; i < count; i++) {
            if( !DecideAlgorithm(client[i], server[i], match[i]) ) 
                return false;
        }
        return true;
    }   

    /* CTransport::DecideAlgorithm
     * Decides what algorithm to used based on the server's and the client's preferred algorithms.
     */
    bool CTransport::DecideAlgorithm
        (
        const std::string & client,     /* client list of algorithms */
        const std::string & server,     /* server list of algorithms */
        std::string & match             /* selected algorithm */
        ) const
    {
        vector<string> cVec, sVec;

        /* Split the strings */
        SplitString(client, cVec, ',');
        SplitString(server, sVec, ',');
        
        /*  Select the first algorithm on the client list that is also on 
            the servers list
        */
        for(vector<string>::const_iterator cIt = cVec.begin(); cIt != cVec.end(); cIt++)
        {
            for(vector<string>::const_iterator sIt = sVec.begin(); sIt != sVec.end(); sIt++)
            {
                /* compare the strings */
                if( (*cIt) == (*sIt) ) {
                    /* found a matching algorithm */
                    match = *sIt;
                    return true;
                }
            }
        }
        /* algorithm mismatch */
        return false;
    }
};