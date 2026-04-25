/*
    omp-auth v0.0.5
    Created with <3 by Kanaru Yuuki,

    omp-auth is authentication system for your gamemodes so you can just ignore making the "login/register system" anymore. 
    It supports both MySQL and SQLite connections, and it only requires your own connection handle instead of re-creating new handle. 
    The password is protected using Bcrypt Algorithm from SyS, so you don't have to worry about password security.

    Copyright (C) 2026 Kanaru Yuuki

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <samp_bcrypt>

#if !defined OMP_AUTH_USE_SQLITE
    #tryinclude <a_mysql>
    #if !defined mysql_included
        #warning mysql not found, using SQLite as the default database.
        #define OMP_AUTH_USE_SQLITE
    #endif
#endif

#if !defined OMP_AUTH_BUFFER_SIZE
    #define OMP_AUTH_BUFFER_SIZE 512
#endif

static stock const OMP_AUTH_DIALOG_ID = 0x412B; // A+

// Connection
static stock
    Auth_g_sConnType,
    MySQL:Auth_g_sMySQLConn,
    DB:Auth_g_sSQLiteConn;

// Tables
static stock
    Auth_g_sTableName[128],
    Auth_g_sIDField[128],
    Auth_g_sUserNameField[128],
    Auth_g_sPasswordField[128];

// User Cache
static stock
    Auth_g_sPlayerID[MAX_PLAYERS],
    Auth_g_sPlayerUserName[MAX_PLAYERS][MAX_PLAYER_NAME],
    Auth_g_sPlayerPassword[MAX_PLAYERS][BCRYPT_HASH_LENGTH];

// States
static stock
    bool:Account_g_sUserDataLoaded[MAX_PLAYERS];

stock bool:Auth_Init({MySQL, DB}:connection, const table[] = "accounts", const idField[] = "id", const userNameField[] = "Username", const passwordField[] = "Password", tag = tagof(connection))
{
    if (tag == tagof(MySQL:))
    {
#if !defined OMP_AUTH_USE_SQLITE
        if (mysql_errno(connection))
        {
            printf("[omp-auth error]: Connection failed! Check your connection before initializing omp-auth.");
            return false;
        }

        Auth_g_sConnType = 1;
        Auth_g_sMySQLConn = MySQL:connection;
        
        Auth_handleMySQL(connection, table, idField, userNameField, passwordField);
        return true;
#else
        return false;
#endif
    }

    if (tag == tagof(DB:))
    {
        if (DB:connection == DB:0)
        {
            return false;
        }

        Auth_g_sConnType = 2;
        Auth_g_sSQLiteConn = DB:connection;

        Auth_HandleSQLite(DB:connection, table, idField, userNameField, passwordField);
        return true;
    }

    return false;
}

stock bool:Auth_IsUserDataLoaded(playerid)
{
    return (IsPlayerConnected(playerid) && Account_g_sUserDataLoaded[playerid] == true);
}

stock bool:Auth_LoadUserData(playerid)
{
    new playerName[MAX_PLAYER_NAME];
    GetPlayerName(playerid, playerName, sizeof(playerName));

    if (Auth_g_sConnType == 1)
    {
        new queryFormat[OMP_AUTH_BUFFER_SIZE];
        mysql_format(Auth_g_sMySQLConn, queryFormat, sizeof(queryFormat), "SELECT %s, %s, %s FROM %s WHERE %s = '%e' LIMIT 1", Auth_g_sIDField, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sTableName, Auth_g_sUserNameField, playerName);
        mysql_tquery(Auth_g_sMySQLConn, queryFormat, #Auth_OnAuthLoadUser__, "i", playerid);
        return true;
    }
    else 
    {
        new DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "SELECT %s, %s, %s FROM %s WHERE %s = '%e' LIMIT 1", Auth_g_sIDField, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sTableName, Auth_g_sUserNameField, playerName);
        
        if (result)
        {
            if (!DB_GetRowCount(result))
            {
                Account_g_sUserDataLoaded[playerid] = false;
                CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, false);
                return true;
            }

            Auth_g_sPlayerID[playerid] = DB_GetFieldInt(result, 0);

            DB_GetFieldString(result, 1, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);
            DB_GetFieldString(result, 2, Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
            DB_FreeResultSet(result);

            Account_g_sUserDataLoaded[playerid] = true;
            CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, true);
            return true;
        }
    }

    return false;
}

stock Auth_ShowLoginDialog(playerid, const title[], const body[], const button1[], const button2[], OPEN_MP_TAGS:...)
{
    const static_args = 5;
    const args_diff = (3 - static_args) * 4;

    static args;
    args = numargs();

    static str[2048];
    const str_size = sizeof(str);

    if (args > static_args)
    {

        while (--args >= static_args)
        {
            #emit LCTRL 5
            #emit LOAD.alt args
            #emit SHL.C.alt 2
            #emit ADD.C 12
            #emit ADD
            #emit LOAD.I
            #emit PUSH.pri
        }

        #emit PUSH.S body
        #emit PUSH.C str_size
        #emit PUSH.C str
        #emit LOAD.S.pri 8
        #emit ADD.C args_diff
        #emit PUSH.pri
        #emit SYSREQ.C format
        #emit LCTRL 5
        #emit SCTRL 4

        return ShowPlayerDialog(playerid, OMP_AUTH_DIALOG_ID, DIALOG_STYLE_PASSWORD, title, str, button1, button2);
    }
    
    return ShowPlayerDialog(playerid, OMP_AUTH_DIALOG_ID, DIALOG_STYLE_PASSWORD, title, body, button1, button2);
}

stock Auth_ShowRegisterDialog(playerid, const title[], const body[], const button1[], const button2[], OPEN_MP_TAGS:...)
{
    const static_args = 5;
    const args_diff = (3 - static_args) * 4;

    static args;
    args = numargs();

    static str[2048];
    const str_size = sizeof(str);

    if (args > static_args)
    {

        while (--args >= static_args)
        {
            #emit LCTRL 5
            #emit LOAD.alt args
            #emit SHL.C.alt 2
            #emit ADD.C 12
            #emit ADD
            #emit LOAD.I
            #emit PUSH.pri
        }

        #emit PUSH.S body
        #emit PUSH.C str_size
        #emit PUSH.C str
        #emit LOAD.S.pri 8
        #emit ADD.C args_diff
        #emit PUSH.pri
        #emit SYSREQ.C format
        #emit LCTRL 5
        #emit SCTRL 4

        return ShowPlayerDialog(playerid, OMP_AUTH_DIALOG_ID + 1, DIALOG_STYLE_PASSWORD, title, str, button1, button2);
    }
    
    return ShowPlayerDialog(playerid, OMP_AUTH_DIALOG_ID + 1, DIALOG_STYLE_PASSWORD, title, body, button1, button2);
}

static stock Auth_handleMySQL(MySQL:connection, const table[], const idField[], const userNameField[], const passwordField[])
{
    new queryFormat[OMP_AUTH_BUFFER_SIZE];
    format(queryFormat, sizeof(queryFormat), "SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = '%s'", table);
    
    new Cache:result = mysql_query(connection, queryFormat);

    if (result)
    {
        new rows;
        cache_get_row_count(rows);
    
        if (!rows)
        {
            mysql_format(connection, queryFormat, sizeof(queryFormat), "CREATE TABLE %s (%s INT NOT NULL PRIMARY KEY AUTO_INCREMENT, %s VARCHAR(24) NOT NULL, %s VARCHAR(60) NOT NULL)", table, idField, userNameField, passwordField);
            new success = mysql_tquery(connection, queryFormat);
            
            if (!success)
            {
                print("[omp-auth error]: Failed to initialize an omp-auth, check your database setting and try again.");
            }

            // Copy everything.
            strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
            strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
            strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
            strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));

            // Skip the field checking, since we're already initializing the table.
            return;
        }

        new
            outputName[64],
            bool:foundIdField = false,
            bool:foundNameField = false,
            bool:foundPasswordField = false;

        for (new i = 0; i < rows; i ++)
        {
            cache_get_value(i, 0, outputName);
            
            if (!strcmp(outputName, idField, false)) foundIdField = true;
            else if (!strcmp(outputName, userNameField, false)) foundNameField = true;
            else if (!strcmp(outputName, passwordField, false)) foundPasswordField = true;
        }

        cache_delete(result);

        if (!foundIdField)
        {
            mysql_format(connection, queryFormat, sizeof(queryFormat), "ALTER TABLE %s ADD %s INT NOT NULL PRIMARY KEY AUTO_INCREMENT", table, idField);
            mysql_query(connection, queryFormat, false);

            if (mysql_errno(connection))
            {
                printf("[omp-auth error]: Failed to initialize id field (%s) in %s!", idField, table);
                return;
            }
        }

        if (!foundNameField)
        {
            mysql_format(connection, queryFormat, sizeof(queryFormat), "ALTER TABLE %s ADD %s VARCHAR(64) NOT NULL", table, userNameField);
            mysql_query(connection, queryFormat, false);

            if (mysql_errno(connection))
            {
                printf("[omp-auth error]: Failed to initialize id field (%s) in %s!", userNameField, table);
                return;
            }
        }

        if (!foundPasswordField)
        {
            mysql_format(connection, queryFormat, sizeof(queryFormat), "ALTER TABLE %s ADD %s VARCHAR(60) NOT NULL", table, passwordField);
            mysql_query(connection, queryFormat, false);

            if (mysql_errno(connection))
            {
                printf("[omp-auth error]: Failed to initialize id field (%s) in %s!", passwordField, table);
                return;
            }
        }
        
        // Copy everything.
        strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
        strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
        strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
        strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));
    }
}

static stock Auth_HandleSQLite(DB:connection, const table[], const idField[], const userNameField[], const passwordField[])
{
    new DBResult:result = DB_ExecuteQuery(connection, "PRAGMA table_info(%s)", table);

    if (result)
    {
        if (!DB_GetRowCount(result))
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "CREATE TABLE IF NOT EXISTS %s (%s INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, %s VARCHAR(24) NOT NULL, %s VARCHAR(60) NOT NULL)", table, idField, userNameField, passwordField));

            if (!success)
            {
                print("[omp-auth error]: Failed to initialize an omp-auth, check your database setting and try again.");
            }
            
            // Copy everything.
            strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
            strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
            strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
            strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));

            // Skip the field checking, since we're already initializing the table.
            return;
        }
        
        new
            outputName[64],
            bool:foundIdField = false,
            bool:foundNameField = false,
            bool:foundPasswordField = false;
        
        do
        {
            DB_GetFieldString(result, 1, outputName, sizeof(outputName));

            if (!strcmp(outputName, idField, false)) foundIdField = true;
            else if (!strcmp(outputName, userNameField, false)) foundNameField = true;
            else if (!strcmp(outputName, passwordField, false)) foundPasswordField = true;
        }
        while (DB_SelectNextRow(result));

        DB_FreeResultSet(result);

        if (!foundIdField)
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "ALTER TABLE %s ADD %s INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT", table, idField));

            if (!success)
            {
                printf("[omp-auth error]: Failed to initialize id field (%s) in %s!", idField, table);
                return;
            }
        }


        if (!foundNameField)
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "ALTER TABLE %s ADD %s VARCHAR(24) NOT NULL", table, userNameField));

            if (!success)
            {
                printf("[omp-auth error]: Failed to initialize username field (%s) in %s!", userNameField, table);
                return;
            }
        }

        if (!foundPasswordField)
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "ALTER TABLE %s ADD %s VARCHAR(60) NOT NULL", table, passwordField));

            if (!success)
            {
                printf("[omp-auth error]: Failed to initialize password field (%s) in %s!", passwordField, table);
                return;
            }
        }

        // Copy everything.
        strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
        strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
        strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
        strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));
    }
}

forward Auth_OnAuthLoadUser__(playerid);
public Auth_OnAuthLoadUser__(playerid)
{
    new rows;
    cache_get_row_count(rows);

    if (!rows)
    {
        Account_g_sUserDataLoaded[playerid] = false;
        CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, false);
        return 0;
    }

    cache_get_value_index_int(0, 0, Auth_g_sPlayerID[playerid]);
    cache_get_value_index(0, 1, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);
    cache_get_value_index(0, 2, Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
    cache_unset_active();

    Account_g_sUserDataLoaded[playerid] = true;
    CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, true);
    return 1;
}

#if defined OnUserAuthDataLoaded
    forward OnUserAuthDataLoaded(playerid, bool:loaded);
#endif
