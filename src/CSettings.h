#ifndef _CSETTINGS_H_
#define _CSETTINGS_H_

#include <string>

enum 
{
    SSHD_SETTING_MOTD_ENABLED,
    SSHD_SETTING_MOTD_FILE,
    SSHD_SETTING_MAX_MOTD_COMMENTS,

    /* Authentication related settings */
    SSHD_SETTING_USER_CHANGE_ALLOWED,               
    SSHD_SETTING_BOGUS_AUTHENTICATION,              
    SSHD_SETTING_AUTHENTICATION_ATTEMPTS,
    SSHD_SETTING_AUTHENTICATION_NONE,
    SSHD_SETTING_AUTHENTICATION_PASSWORD,
    SSHD_SETTING_AUTHENTICATION_PK,

    SSHD_SETTING_PREFERRED_KEYEXCHANGE,
    SSHD_SETTING_PREFERRED_HOSTKEY,
    SSHD_SETTING_PREFERRED_CIPHER,
    SSHD_SETTING_PREFERRED_HMAC,

    SSHD_SETTING_SOFTWARE_NAME,
    SSHD_SETTING_SOFTWARE_VERSION,

    SSHD_SETTING_RSA_PUBLIC_KEY_FILE,           /* Server's private RSA key file */
    SSHD_SETTING_RSA_PRIVATE_KEY_FILE,          /* Server's public RSA key file */

    /* new settings must be added before this */
    SSHD_SETTING_MAX
};

namespace ssh
{
    /* Class:           CSettings
     * Description:     Stores the settings.
     */
    class CSettings
    {
    public:
        CSettings();

        bool load(const char *);    /* loads the settings from a file */

        bool StoreString(int, const std::string &);
        bool StoreValue(int, int);

        bool GetString(int, std::string &) const;       /* reads a stored string */
        bool GetValue(int, int &) const;                /* reads a stored integer value */

    protected:

        enum {
            SETTING_NO_VALUE = 0,
            SETTING_STRING_VALUE,
            SETTING_INT_VALUE,
        };

        struct Element {
            std::string     sValue; /* stores string settings */
            int             iValue; /* stores integer settings */
            int             type;
        };

        Element settings[SSHD_SETTING_MAX];
    };
};

#endif