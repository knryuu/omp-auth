/*
    omp-auth v1.0.1
    Created with <3 by knryuu.

    omp-auth is authentication system for your gamemodes so you can 
    just ignore making the "login/register system" anymore. It supports 
    both MySQL and SQLite connections, and it only requires your own 
    connection handle instead of re-creating new handle. The password 
    is protected using Bcrypt Algorithm from SyS, so you don't have to 
    worry about password security.

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

#if !defined OMP_AUTH_MIN_PASSWORD_INPUT
    #define OMP_AUTH_MIN_PASSWORD_INPUT 6
#endif

// Const
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
    Auth_g_sPlayerUserName[MAX_PLAYERS][MAX_PLAYER_NAME + 1],
    Auth_g_sPlayerPassword[MAX_PLAYERS][BCRYPT_HASH_LENGTH];

// States
static stock
    bool:Auth_g_sUserDataLoaded[MAX_PLAYERS],
    bool:Auth_g_sUserDataAuthed[MAX_PLAYERS];

// Error IDs
#define OMP_AUTH_ERROR: __TAG(OMP_AUTH_ERROR):
enum OMP_AUTH_ERROR:__OMP_AUTH_ERROR
{
    OMP_AUTH_NO_ERROR = 0,
    OMP_AUTH_EMPTY_PASSWORD = 1,
    OMP_AUTH_MIN_PASSWORD,
    OMP_AUTH_WRONG_PASSWORD,
    OMP_AUTH_USER_EXITED,
    OMP_AUTH_FAIL_REGISTER
};

// Forward Internal
forward Auth_OnLoadUser__(playerid);
forward Auth_OnPrepareRegister__(playerid, hashid);
forward Auth_OnRegisterUser__(playerid);
forward Auth_OnVerifyLogin__(playerid, bool:success);

// Macros
#define IS_NULL(%0) ((%0[(%0[0])=='\1'])=='\0'||(%0[0])==ucharmax+1)

// Initializations
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

// Gets & Sets
stock bool:Auth_IsUserDataLoaded(playerid)
{
    if (!IsPlayerConnected(playerid))
        return false;
    
    return (Auth_g_sUserDataLoaded[playerid] == true);
}

stock bool:Auth_IsUserLoggedIn(playerid)
{
    if (!IsPlayerConnected(playerid))
        return false;
    
    return (Auth_g_sUserDataAuthed[playerid] == true);
}

stock bool:Auth_GetUserID(playerid, &uid)
{
    if (!Auth_IsUserDataLoaded(playerid))
        return false;
    
    uid = Auth_g_sPlayerID[playerid];
    return true;
}

stock bool:Auth_GetUserName(playerid, name[], len = sizeof(name))
{
    if (!Auth_IsUserDataLoaded(playerid))
        return false;
    
    strcopy(name, Auth_g_sPlayerUserName[playerid], len);
    return true;
}

stock bool:Auth_SetUserName(playerid, const name[], bool:sync = false)
{
    if (!Auth_IsUserDataLoaded(playerid))
        return false;
    
    strcopy(Auth_g_sPlayerUserName[playerid], name, MAX_PLAYER_NAME);
    
#if defined mysql_included
    if (Auth_g_sConnType == 1)
    {
        new queryFormat[OMP_AUTH_BUFFER_SIZE];
        mysql_format(Auth_g_sMySQLConn, queryFormat, sizeof(queryFormat), "UPDATE %s SET %s = '%s' WHERE %s = '%d'", Auth_g_sTableName, Auth_g_sUserNameField, name, Auth_g_sIDField, Auth_g_sPlayerID[playerid]);
        mysql_tquery(Auth_g_sMySQLConn, queryFormat);
    }
    else
    {
        DB_FreeResultSet(DB_ExecuteQuery(Auth_g_sSQLiteConn, "UPDATE %s SET %s = '%s' WHERE %s = '%d'", Auth_g_sTableName, Auth_g_sUserNameField, name, Auth_g_sIDField, Auth_g_sPlayerID[playerid]));
    }
#else
    DB_FreeResultSet(DB_ExecuteQuery(Auth_g_sSQLiteConn, "UPDATE %s SET %s = '%s' WHERE %s = '%d'", Auth_g_sTableName, Auth_g_sUserNameField, name, Auth_g_sIDField, Auth_g_sPlayerID[playerid]));
#endif

    if (sync == true)
        SetPlayerName(playerid, name);

    return true;
}

// Our reset state
stock Auth_ResetData(playerid)
{
    new uid = Auth_g_sPlayerID[playerid] = 0;
    
    Auth_MemSet(Auth_g_sPlayerUserName[playerid], 0, sizeof(Auth_g_sPlayerUserName[]));
    Auth_MemSet(Auth_g_sPlayerPassword[playerid], 0, sizeof(Auth_g_sPlayerPassword[]));
    Auth_g_sUserDataLoaded[playerid] = false;
    Auth_g_sUserDataAuthed[playerid] = false;

    CallRemoteFunction(#OnUserAuthResetData, "ii", playerid, uid);
    return 1;
}

// Controller
stock bool:Auth_LoadUserData(playerid)
{
    new playerName[MAX_PLAYER_NAME];
    GetPlayerName(playerid, playerName, sizeof(playerName));
    
#if defined mysql_included
    if (Auth_g_sConnType == 1)
    {
        new queryFormat[OMP_AUTH_BUFFER_SIZE];
        mysql_format(Auth_g_sMySQLConn, queryFormat, sizeof(queryFormat), "SELECT %s, %s, %s FROM %s WHERE %s = '%e' LIMIT 1", Auth_g_sIDField, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sTableName, Auth_g_sUserNameField, playerName);
        mysql_tquery(Auth_g_sMySQLConn, queryFormat, #Auth_OnLoadUser__, "i", playerid);
        return true;
    }
    else 
    {
        new DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "SELECT %s, %s, %s FROM %s WHERE %s = '%q' LIMIT 1", Auth_g_sIDField, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sTableName, Auth_g_sUserNameField, playerName);
        
        if (result)
        {
            if (!DB_GetRowCount(result))
            {
                Auth_g_sUserDataLoaded[playerid] = false;
                CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, 0);
                return true;
            }

            Auth_g_sPlayerID[playerid] = DB_GetFieldInt(result, 0);
            DB_GetFieldString(result, 1, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);
            DB_GetFieldString(result, 2, Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
            DB_FreeResultSet(result);

            Auth_g_sUserDataLoaded[playerid] = true;
            CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, Auth_g_sPlayerID[playerid]);
            return true;
        }
    }
#else
    new DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "SELECT %s, %s, %s FROM %s WHERE %s = '%q' LIMIT 1", Auth_g_sIDField, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sTableName, Auth_g_sUserNameField, playerName);
    
    if (result)
    {
        if (!DB_GetRowCount(result))
        {
            Auth_g_sUserDataLoaded[playerid] = false;
            CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, 0);
            return true;
        }

        Auth_g_sPlayerID[playerid] = DB_GetFieldInt(result, 0);
        DB_GetFieldString(result, 1, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);
        DB_GetFieldString(result, 2, Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
        DB_FreeResultSet(result);

        Auth_g_sUserDataLoaded[playerid] = true;
        CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, Auth_g_sPlayerID[playerid]);
        return true;
    }
#endif

    return false;
}

// GUI
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

// Internals
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

// Public Internals
#if defined mysql_included
public Auth_OnLoadUser__(playerid)
{
    new rows;
    cache_get_row_count(rows);

    if (!rows)
    {
        Auth_g_sUserDataLoaded[playerid] = false;
        CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, 0);
        return 0;
    }

    cache_get_value_index_int(0, 0, Auth_g_sPlayerID[playerid]);
    cache_get_value_index(0, 1, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);
    cache_get_value_index(0, 2, Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
    cache_unset_active();

    Auth_g_sUserDataLoaded[playerid] = true;
    CallRemoteFunction(#OnUserAuthDataLoaded, "ii", playerid, Auth_g_sPlayerID[playerid]);
    return 1;
}
#endif

public Auth_OnPrepareRegister__(playerid, hashid)
{
    Auth_g_sUserDataLoaded[playerid] = true;
    bcrypt_get_hash(Auth_g_sPlayerPassword[playerid], BCRYPT_HASH_LENGTH);
    GetPlayerName(playerid, Auth_g_sPlayerUserName[playerid], MAX_PLAYER_NAME);

#if defined mysql_included
    if (Auth_g_sConnType == 1)
    {
        new queryFormat[OMP_AUTH_BUFFER_SIZE];
        mysql_format(Auth_g_sMySQLConn, queryFormat, sizeof(queryFormat), "INSERT INTO %s (%s, %s) VALUES ('%e', '%e')", Auth_g_sTableName, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sPlayerUserName[playerid], Auth_g_sPlayerPassword[playerid]);
        mysql_tquery(Auth_g_sMySQLConn, queryFormat, #Auth_OnRegisterUser__, "i", playerid);
    }
    else
    {
        new DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "INSERT INTO %s (%s, %s) VALUES ('%q', '%q')", Auth_g_sTableName, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sPlayerUserName[playerid], Auth_g_sPlayerPassword[playerid]);
        
        if (result)
        {
            Auth_g_sPlayerID[playerid] = Auth_GetSQLiteLastInsertID();
            DB_FreeResultSet(result);

            CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_NO_ERROR);
        }
        else
        {
            Auth_ResetData(playerid);
            printf("[omp-auth error]: Failed to insert user data to %s", Auth_g_sTableName);
            CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, 0, OMP_AUTH_FAIL_REGISTER);
        }
    }
#else
    new DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "INSERT INTO %s (%s, %s) VALUES ('%q', '%q')", Auth_g_sTableName, Auth_g_sUserNameField, Auth_g_sPasswordField, Auth_g_sPlayerUserName[playerid], Auth_g_sPlayerPassword[playerid]);
    
    if (result)
    {
        Auth_g_sPlayerID[playerid] = Auth_GetSQLiteLastInsertID();
        DB_FreeResultSet(result);

        CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_NO_ERROR);
    }
    else
    {
        Auth_ResetData(playerid);
        printf("[omp-auth error]: Failed to insert user data to %s", Auth_g_sTableName);
        CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, 0, OMP_AUTH_FAIL_REGISTER);
    }
#endif

    return 1;
}

#if defined mysql_included
public Auth_OnRegisterUser__(playerid)
{
    Auth_g_sPlayerID[playerid] = cache_insert_id();
    CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_NO_ERROR);
    return 1;
}
#endif

public Auth_OnVerifyLogin__(playerid, bool:success)
{
    if (success)
    {
        // Reset now if it's not used.
        Auth_MemSet(Auth_g_sPlayerPassword[playerid], 0, sizeof(Auth_g_sPlayerPassword[]));
        CallRemoteFunction(#OnAuthUserLogin, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_NO_ERROR);
        return 1;
    }

    CallRemoteFunction(#OnAuthUserLogin, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_WRONG_PASSWORD);
    return 1;
}

// Internal gui hooks
public OnDialogResponse(playerid, dialogid, response, listitem, inputtext[])
{
    if (dialogid == OMP_AUTH_DIALOG_ID)
    {
        if (!response)
        {
            Auth_ResetData(playerid);
            Kick(playerid);
            return 1;
        }

        if (IS_NULL(inputtext))
        {
            CallRemoteFunction(#OnAuthUserLogin, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_EMPTY_PASSWORD);
            return 1;
        }

        bcrypt_verify(playerid, #Auth_OnVerifyLogin__, inputtext, Auth_g_sPlayerPassword[playerid]);
        return 1;
    }

    if (dialogid == OMP_AUTH_DIALOG_ID+1)
    {
        if (!response)
        {
            Auth_ResetData(playerid);
            Kick(playerid);
            return 1;
        }

        if (IS_NULL(inputtext))
        {
            CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_EMPTY_PASSWORD);
            return 1;
        }

        if (strlen(inputtext) < OMP_AUTH_MIN_PASSWORD_INPUT)
        {
            CallRemoteFunction(#OnAuthUserRegister, "iii", playerid, Auth_g_sPlayerID[playerid], OMP_AUTH_MIN_PASSWORD);
            return 1;
        }

        bcrypt_hash(playerid, #Auth_OnPrepareRegister__, inputtext, BCRYPT_COST);
        return 1;        
    }


    #if defined AU_OnDialogResponse
        return AU_OnDialogResponse(playerid, dialogid, response, listitem, inputtext);
    #else
        return 0;
    #endif
}

public OnPlayerDisconnect(playerid, reason)
{
    Auth_ResetData(playerid);

    #if defined AU_OnPlayerDisconnect
        return AU_OnPlayerDisconnect(playerid, reason);
    #else
        return 1;
    #endif
}

// Deep Internal functions for various reasons
static stock Auth_GetSQLiteLastInsertID()
{
    new 
        DBResult:result = DB_ExecuteQuery(Auth_g_sSQLiteConn, "SELECT last_insert_rowid()"),
        ret;
    
    ret = DB_GetFieldInt(result, 0);
    DB_FreeResultSet(result);
    return ret;
}


static stock Auth_MemSet(variable[], cells, value) 
{
    new address;
    
    #emit LOAD.S.pri  variable
    #emit STOR.S.pri  address
    
    Auth_RawMemSet(address, cells, value);
}

static stock Auth_RawMemSet(address, cells, value) 
{
    new param_adr;
    
    #emit LCTRL       6
    #emit MOVE.alt
    #emit LCTRL       0
    #emit ADD
    #emit MOVE.alt
    #emit LCTRL       1
    #emit SUB.alt
    #emit ADD.C       92
    #emit STOR.S.pri  param_adr
    #emit LOAD.S.pri  cells
    #emit SHL.C.pri   2
    #emit SREF.S.pri  param_adr
    
    #emit LOAD.S.alt  address
    #emit LOAD.S.pri  value
    #emit FILL        0
}

// ALS Controller
#if defined _ALS_OnDialogResponse
    #undef OnDialogResponse
#else
    #define _ALS_OnDialogResponse
#endif

#define OnPlayerDisconnect AU_OnPlayerDisconnect

#if defined _ALS_OnPlayerDisconnect
    #undef OnPlayerDisconnect
#else
    #define _ALS_OnPlayerDisconnect
#endif

#define OnPlayerDisconnect AU_OnPlayerDisconnect

// Forwards
#if defined AU_OnDialogResponse
    forward AU_OnDialogResponse(playerid, dialogid, response, listitem, inputtext[]);
#endif

#if defined AU_OnPlayerDisconnect
    forward AU_OnPlayerDisconnect(playerid, reason);
#endif

#if defined OnUserAuthDataLoaded
    forward OnUserAuthDataLoaded(playerid, uid);
#endif

#if defined OnUserAuthResetData
    forward OnUserAuthResetData(playerid, uid);
#endif

#if defined OnAuthUserRegister
    forward OnAuthUserRegister(playerid, uid, OMP_AUTH_ERROR:error);
#endif

#if defined OnAuthUserLogin
    forward OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error);
#endif

// Automations
#if !defined OMP_AUTH_AUTO_HANDLE
    #endinput
#endif

#if !defined OMP_AUTH_MAX_ATTEMPT
    #define OMP_AUTH_MAX_ATTEMPT 3
#endif

#if !defined OMP_AUTH_LOGIN_DIALOG_TITLE
    #define OMP_AUTH_LOGIN_DIALOG_TITLE "{FFFFFF}User Login"
#endif

#if !defined OMP_AUTH_LOGIN_DIALOG_BODY
    #define OMP_AUTH_LOGIN_DIALOG_BODY "{FFFFFF}Welcome back to our server! Please insert your password below in order to login\n{acacac}(NOTE: You only have %d chances before getting kicked from the server)"
#endif

#if !defined OMP_AUTH_REGISTER_DIALOG_TITLE
    #define OMP_AUTH_REGISTER_DIALOG_TITLE "{FFFFFF}User Register"
#endif

#if !defined OMP_AUTH_REGISTER_DIALOG_BODY
    #define OMP_AUTH_REGISTER_DIALOG_BODY "{FFFFFF}Welcome to our server! Please insert your password below in order to register\n{acacac}(NOTE: The minimum password requirement is %d)"
#endif

#if !defined OMP_AUTH_EMPTY_MESSAGE
    #define OMP_AUTH_EMPTY_MESSAGE  "{FF0000}ERROR: Invalid input specified, please try again!"
#endif

#if !defined OMP_AUTH_FAIL_MESSAGE
    #define OMP_AUTH_FAIL_MESSAGE  "{FF0000}ERROR: Invalid password specified, please try again!"
#endif

#if !defined OMP_AUTH_REQ_MESSAGE
    #define OMP_AUTH_REQ_MESSAGE   "{FF0000}ERROR: Your password is less than the requirement, please try again!"
#endif

static Account_g_sAuthAttempt[MAX_PLAYERS] = {0, ...};

stock void:ClearMessageChat(playerid, amount = 10)
{
    for (new i = 0; i < amount; i ++) SendClientMessage(playerid, -1, " ");
}

public OnUserAuthDataLoaded(playerid, uid)
{
    if (uid == 0)
    {
        ClearMessageChat(playerid);
        Auth_ShowRegisterDialog(playerid, OMP_AUTH_REGISTER_DIALOG_TITLE, OMP_AUTH_REGISTER_DIALOG_BODY, "Register", "Exit", OMP_AUTH_MIN_PASSWORD_INPUT);
    }
    else
    {
        ClearMessageChat(playerid);
        Auth_ShowLoginDialog(playerid, OMP_AUTH_LOGIN_DIALOG_TITLE, OMP_AUTH_LOGIN_DIALOG_BODY, "Login", "Exit", OMP_AUTH_MAX_ATTEMPT);
    }
    return 1;
}

public OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_EMPTY_PASSWORD)
    {
        Auth_ShowLoginDialog(playerid, OMP_AUTH_LOGIN_DIALOG_TITLE, OMP_AUTH_EMPTY_MESSAGE"\n\n"OMP_AUTH_LOGIN_DIALOG_BODY, "Login", "Exit", OMP_AUTH_MAX_ATTEMPT);
        return 1;
    }

    if (error == OMP_AUTH_WRONG_PASSWORD)
    {
        if (++ Account_g_sAuthAttempt[playerid] >= 3)
        {
            Kick(playerid);
            return 0;
        }

        Auth_ShowLoginDialog(playerid, OMP_AUTH_LOGIN_DIALOG_TITLE, OMP_AUTH_FAIL_MESSAGE"\n\n"OMP_AUTH_LOGIN_DIALOG_BODY, "Login", "Exit", OMP_AUTH_MAX_ATTEMPT);
        return 1;
    }

    Account_g_sAuthAttempt[playerid] = 0;

    #if defined AU_OnAuthUserLogin
        return AU_OnAuthUserLogin(playerid, uid, error);
    #else
        return 1;
    #endif
}

public OnAuthUserRegister(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_EMPTY_PASSWORD)
    {
        Auth_ShowRegisterDialog(playerid, OMP_AUTH_REGISTER_DIALOG_TITLE, OMP_AUTH_EMPTY_MESSAGE"\n\n"OMP_AUTH_REGISTER_DIALOG_BODY, "Register", "Exit", OMP_AUTH_MIN_PASSWORD_INPUT);
        return 1;
    }

    if (error == OMP_AUTH_MIN_PASSWORD)
    {
        Auth_ShowRegisterDialog(playerid, OMP_AUTH_REGISTER_DIALOG_TITLE, OMP_AUTH_REQ_MESSAGE"\n\n"OMP_AUTH_REGISTER_DIALOG_BODY, "Register", "Exit", OMP_AUTH_MIN_PASSWORD_INPUT);
        return 1;
    }

    Auth_ShowLoginDialog(playerid, OMP_AUTH_LOGIN_DIALOG_TITLE, OMP_AUTH_LOGIN_DIALOG_BODY, "Login", "Exit", OMP_AUTH_MAX_ATTEMPT);

    #if defined AU_OnAuthUserRegister
        return AU_OnAuthUserRegister(playerid, uid, error);
    #else
        return 1;
    #endif
}

public OnUserAuthResetData(playerid, uid)
{
    Account_g_sAuthAttempt[playerid] = 0;
 
    #if defined AU_OnUserAuthResetData
        return AU_OnUserAuthResetData(playerid, uid);
    #else
        return 1;
    #endif
}

#if defined _ALS_OnAuthUserLogin
    #undef OnAuthUserLogin
#else
    #define _ALS_OnAuthUserLogin
#endif

#define OnAuthUserLogin AU_OnAuthUserLogin

#if defined _ALS_OnAuthUserRegister
    #undef OnAuthUserRegister
#else
    #define _ALS_OnAuthUserRegister
#endif

#define OnAuthUserRegister AU_OnAuthUserRegister

#if defined _ALS_OnUserAuthResetData
    #undef OnUserAuthResetData
#else
    #define _ALS_OnUserAuthResetData
#endif

#define OnUserAuthResetData AU_OnUserAuthResetData

#if defined AU_OnAuthUserRegister
    forward AU_OnAuthUserRegister(playerid, uid, OMP_AUTH_ERROR:error);
#endif

#if defined AU_OnAuthUserLogin
    forward AU_OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error);
#endif

#if defined AU_OnUserAuthResetData
    forward AU_OnUserAuthResetData(playerid, uid);
#endif
