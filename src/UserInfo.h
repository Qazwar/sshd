#ifndef _USERINFO_H_
#define _USERINFO_H_

namespace ssh
{
    /* UserInfo
     * Contains authentication information about a user.
     */
    typedef struct _UserInfo
    {
        uint8_t     pwd[20];    /* sha-1 hashed password + salt , only available if the corresponding mask in authMask is set */
        uint32_t    authMask;
    } UserInfo;
};

#endif