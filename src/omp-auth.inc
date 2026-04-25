
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

            strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
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

            strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
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

            strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));
        }
        
        strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
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

            strcopy(Auth_g_sIDField, idField, sizeof(Auth_g_sIDField));
        }


        if (!foundNameField)
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "ALTER TABLE %s ADD %s VARCHAR(24) NOT NULL", table, userNameField));

            if (!success)
            {
                printf("[omp-auth error]: Failed to initialize username field (%s) in %s!", userNameField, table);
                return;
            }
            
            strcopy(Auth_g_sUserNameField, userNameField, sizeof(Auth_g_sUserNameField));
        }

        if (!foundPasswordField)
        {
            new bool:success = DB_FreeResultSet(DB_ExecuteQuery(connection, "ALTER TABLE %s ADD %s VARCHAR(60) NOT NULL", table, passwordField));

            if (!success)
            {
                printf("[omp-auth error]: Failed to initialize password field (%s) in %s!", passwordField, table);
                return;
            }
            
            strcopy(Auth_g_sPasswordField, passwordField, sizeof(Auth_g_sPasswordField));
        }

        strcopy(Auth_g_sTableName, table, sizeof(Auth_g_sTableName));
    }
}
