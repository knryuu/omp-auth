/*
 *  @Name: omp_auth.inc
 *  @Version: 0.0.1
 *  @Author: Kanaru Yuuki
 *  @Date: 04/07/2025
 * 
 *  omp-auth is a simple login-register system that 
 *  you can use by just focusing on the dialog and 
 *  let the rest of the implementation be handled internally 
 *  by this include! 
 *
 *  Copyright (C) <year>  <name of author>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <open.mp>
#include <PawnPlus>
#include <pp-mysql>

static stock
    MySQL:Account_g_SqlHandle,
    Account_g_SqlTable[64]
    Account_g_SqlTableRowId[64],
    Account_g_SqlTableRowName[64],
    Account_g_SqlTableRowPassword[64],
    Account_g_MinimumPassLength;

static stock
    bool:Account_g_LoggedIn[MAX_PLAYERS],
    Cache:Account_g_Cache[MAX_PLAYERS],
    Account_g_Id[MAX_PLAYERS],
    Account_g_Name[MAX_PLAYERS][MAX_PLAYER_NAME + 1];

stock void:Account_Config(MySQL:handle = MYSQL_DEFAULT_HANDLE, minimumPassLength = 5, const tableName[] = "YUU_accounts", const rowId[] = "id", const rowName[] = "username", const rowPassword[] = "password")
{
    if (handle == MYSQL_INVALID_HANDLE || mysql_errno(handle))
    {
        print("[ACCOUNT-SYSTEM ERROR]: MySQL isn't connected to the database!");
        return;
    }
    
    await mysql_aquery_s(handle, str_format("CREATE TABLE IF NOT EXISTS %e (%e INT NOT NULL PRIMARY KEY AUTO_INCREMENT, %e VARCHAR(24) NOT NULL, %e VARCHAR(60) NOT NULL)", rowId, rowName, rowPassword));
    Account_g_SqlHandle = handle;
    strcopy(Account_g_SqlTable, tableName, 64);
    strcopy(Account_g_SqlTableRowId, rowId, 64);
    strcopy(Account_g_SqlTableRowName, rowName, 64);
    strcopy(Account_g_SqlTableRowPassword, rowPassword, 64);
    Account_g_MinimumPassLength = minimumPassLength;
    print("[ACCOUNT-SYSTEM INFO]: Initialized!");
}

stock bool:Account_Exists(playerid)
{
    if (!IsPlayerConnected(playerid))
    {
        return false;
    }
    
    return (!!Account_g_Id[playerid]);
    
}

stock bool:Account_IsLoggedIn(playerid)
{
    if (!Account_Exists(playerid))
    {
        return false;
    }
    
    return (Account_g_LoggedIn[playerid]);
}


stock bool:Account_GetId(playerid, &id)
{
    if (!Account_IsLoggedIn(playerid))
    {
        return false;
    }
    
    id = Account_g_Id[playerid];
    return true;
}

stock bool:Account_GetName(playerid, name[], len = sizeof name)
{
    if (!Account_IsLoggedIn(playerid))
    {
        return false;
    }
    
    strcopy(name, Account_g_Name[playerid], len);
    return true;
}

stock bool:Account_SetName(playerid, const newName[])
{
    if (!Account_IsLoggedIn(playerid))
    {
        return false;
    }
    
    new 
        oldName[MAX_PLAYER_NAME + 1],
        playerName[MAX_PLAYER_NAME + 1];
        
    strcopy(oldName, Account_g_Name[playerid]);
    GetPlayerName(playerid, playerName);
    
    new szSqlUpdate[256];
    mysql_format(Account_g_SqlHandle, szSqlUpdate, sizeof szSqlUpdate, "UPDATE %s SET %s = '%e' WHERE %s = '%e'", 
        Account_g_SqlTable,
        Account_g_SqlTableRowName,
        name,
        Account_g_SqlTableRowName,
        oldName
    );
    mysql_pquery(Account_g_SqlHandle, szSqlUpdate, "", "");    
    
    // Update the name if not matched with previous name
    if (strcmp(oldName, playerName, false))
    {
        SetPlayerName(playerid, name);
    }
    
    strcopy(Account_g_Name[playerid], name, MAX_PLAYER_NAME));
    return true;
}

stock bool:Account_CheckPlayer(playerid)
{
    if (!IsPlayerConnected(playerid))
    {
        return false;
    }
    
    new playerName[MAX_PLAYER_NAME + 1];
    GetPlayerName(playerid, playerName);
    await mysql_aquery_s(handle, str_format("SELECT * FROM %s WHERE %s = '%e'", Account_g_SqlTable, Account_g_SqlTableRowName, playerName));

    new rows;
    cache_get_row_count(rows);
    CallRemoteFunction("OnPlayerAccountChecked", "ii", playerid, rows);

    if (!rows)
    {
        // return early.
        return true;
    }

    // save cache for later.
    Account_g_Cache[playerid] = cache_save();
    cache_get_value_int(0, string:Account_g_SqlTableRowId, Account_g_Id[playerid]);
    cache_get_value(0, string:Account_g_SqlTableRowName, Account_g_Name[playerid]);
    cache_unset_active();
    return true;
}

stock bool:Account_Login(playerid, const password[])
{
    if (!Account_Exists(playerid))
    {
        print("[ACCOUNT-SYSTEM ERROR]: You shouldn't call this when the user doesn't have the account data!");
        return false;
    }
    
    if (IsNull(password))
    {
        return false;
    }
    
    if (!cache_is_valid(Account_g_Cache[playerid]))
    {
        new playerName[MAX_PLAYER_NAME + 1];
        GetPlayerName(playerid, playerName);
        await mysql_aquery_s(Account_g_SqlHandle, str_format("SELECT * FROM %s WHERE %s = '%e'", Account_g_SqlTable, Account_g_SqlTableRowName, playerName));

        if (!cache_num_rows())
        {
            printf("[ACCOUNT-SYSTEM ERROR]: User account for %s is gone!", playerName);
            return 0;
        }

        Account_g_Cache[playerid] = cache_save();
        cache_get_value_int(0, string:Account_g_SqlTableRowId, Account_g_Id[playerid]);
        cache_get_value(0, string:Account_g_SqlTableRowName, Account_g_Name[playerid]);
    }
    else
    {
        cache_set_active(Account_g_Cache[playerid]);
    }
    
    new hash[BCRYPT_HASH_LENGTH];
    cache_get_value(0, string:Account_g_SqlTableRowPassword, hash);
    cache_unset_active();
    
    new Task:bcrypt_task = task_new();
    new ret = bcrypt_verify(playerid, "OnAccountVerifyPass__", "d", _:bcrypt_task);
    
    if (!ret)
    {
        task_set_error_ms(bcrypt_task, amx_err_exit, 0);
        return false;
    }
    
    new success = await bcrypt_task;
    
    if (success)
    {
        cache_delete(Account_g_Cache[playerid]);
        Account_g_Cache[playerid] = MYSQL_INVALID_CACHE;
        Account_g_LoggedIn[playerid] = true;
        CallRemoteFunction("OnPlayerAccountLogin", "ii", playerid, Account_g_Id[playerid]);
        return true;
    }
    
    return false;
}

stock bool:Account_Register(playerid, const password[])
{
    if (Account_Exists(playerid))
    {
        print("[ACCOUNT-SYSTEM ERROR]: You shouldn't call this when the user does have the account data!");
        return false;
    }
    
    if (strlen(password) < Account_g_MinimumPassLength)
    {
        return false;
    }
    
    new Task:bcrypt_task = task_new();
    bcrypt_hash(playerid, "OnAccountHashedPass__", password, BCRYPT_COST, "d", _:bcrypt_task);
    
    new hash[BCRYPT_HASH_LENGTH];
    task_await_arr(bcrypt_task, hash);
    
    await mysql_aquery_s(Account_g_SqlHandle, "INSERT INTO %s (%s,%s) VALUES ('%e','%s')", Account_g_SqlTable, Account_g_SqlTableRowName, Account_g_SqlTableRowPassword, playerName, hash);
    CallRemoteFunction("OnAccountRegistered", "ii", playerid, cache_insert_id());
    return true;
}

stock void:Account_Logout(playerid)
{
    if (cache_is_valid(Account_g_Cache[playerid]))
    {
        cache_delete(Account_g_Cache[playerid]);
    }
    
    new id = Account_g_Id[playerid];
    
    Account_g_Id[playerid] = 0;
    Account_g_Name[playerid][0] = 0;
    Account_g_LoggedIn[playerid] = false;
    
    CallRemoteFunction("OnPlayerAccountLogout", "ii", playerid, id);
}
