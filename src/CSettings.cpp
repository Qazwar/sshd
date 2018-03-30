/* CSettings.cpp
 * Handles the different settings.
 *
 * Copyright (c) 2009 Magnus Leksell, all rights reserved.
 */

/* project settings */
#include "CSettings.h"

using namespace std;

namespace ssh
{
    /* CSettings::load
     * Loads the settings from a file.
     */
    bool CSettings::load( const char * name )
    {
        /* TODO */
        return true;
    }

    /* CSettings::CSettings
     * Performs the required initialization.
     */
    CSettings::CSettings()
    {
        for(int i = 0; i < SSHD_SETTING_MAX; i++)
            settings[i].type = SETTING_NO_VALUE;
    }

    /* CSettings::StoreString
     *
     */
    bool CSettings::StoreString(int setting, const string & str)
    {
        settings[setting].sValue    = str;
        settings[setting].type      = SETTING_STRING_VALUE;

        return true;
    }

    /* CSettings::StoreValue
     *
     */
    bool CSettings::StoreValue(int setting, int value)
    {
        settings[setting].iValue = value;
        settings[setting].type = SETTING_INT_VALUE;

        return true;
    }

    /* CSettings::GetString
     *
     */
    bool CSettings::GetString(int setting, string & str) const
    {
        if( settings[setting].type != SETTING_STRING_VALUE )
            return false;
        str = settings[setting].sValue;
        return true;
    }

    /* CSettings::GetValue
     *
     */
    bool CSettings::GetValue(int setting, int & value) const
    {
        if( settings[setting].type != SETTING_INT_VALUE )
            return false;
        value = settings[setting].iValue;
        return true;
    }
};