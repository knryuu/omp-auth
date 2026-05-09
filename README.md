# Open Multiplayer Authentication System

Simple authentication system for [open.mp](https://www.open.mp/) gamemodes.

This include is designed so you can just ignore making the "login/register system" 
anymore. It supports both MySQL and SQLite connections, and it only requires your own 
connection handle instead of re-creating new handle. The password is protected using 
Bcrypt Algorithm from SyS, so you don't have to worry about password security.

### Features
- MySQL and SQLite support — use your existing connection handle
- Passwords hashed with bcrypt via `samp_bcrypt`
- Pre‑built dialogs for login and registration
- Minimal setup, just init, load, and handle callbacks

## Installation
1. Install [`samp_bcrypt`](https://github.com/Sreyas-Sreelal/samp-bcrypt).
2. For MySQL, install [`a_mysql`](https://github.com/pBlueG/SA-MP-MySQL). If `a_mysql` is not found, the system automatically falls back to SQLite.
3. Place `omp-auth.inc` in your `qawno/include` folder and add `#include <omp-auth>` to your script.

## Quick Usage

```pawn
#include <omp-auth>

// MySQL connection
new MySQL:g_Database;

public OnGameModeInit()
{
    // Connect to your database (MySQL example)
    g_Database = mysql_connect("localhost", "root", "", "mydb");
    Auth_Init(g_Database);
    return 1;
}

public OnPlayerConnect(playerid)
{
    // Trigger user data loading
    Auth_LoadUserData(playerid);
    return 1;
}

// Called when user data is loaded (or not found)
public OnUserAuthDataLoaded(playerid, uid)
{
    if (uid == 0)
    {
        new playerName[MAX_PLAYER_NAME + 1];
        GetPlayerName(playerid, playerName, sizeof(playerName));

        // No account → show registration dialog
        Auth_ShowRegisterDialog(playerid, "Register", "{FFFFFF}Welcome %s! Type a password:", "Register", "Quit", playerName);
    }
    else
    {
        new playerName[MAX_PLAYER_NAME + 1];
        GetPlayerName(playerid, playerName, sizeof(playerName));

        // Existing account → show login dialog
        Auth_ShowLoginDialog(playerid, "Login", "{FFFFFF}Welcome back %s! Enter your password:", "Login", "Quit", playerName);
    }
    return 1;
}

// Called after a registration attempt
public OnAuthUserRegister(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_NO_ERROR)
    {
        // Registration success — uid is the new account ID
        SendClientMessage(playerid, -1, "Registered! You are now logged in (User ID: %d).", uid);
        return 1;
    }

    // Handle error here (empty password, too short, DB failure)
}

// Called after a login attempt
public OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_NO_ERROR)
    {
        // Login success — uid is the account ID
        SendClientMessage(playerid, -1, "Logged in successfully!");
        return 1;
    }

    // Handle wrong password, empty input, etc.
}

// Optional: catch when data is reset (player kicked during dialog, etc.)
public OnUserAuthResetData(playerid, uid)
{
    // Clean up any additional player data you stored
    return 1;
}
```

## Configuration Macros

If you want to change the default value, define these **before** including `omp-auth`:

| Macro | Default | Description |
|-------|---------|-------------|
| `OMP_AUTH_USE_SQLITE` | _not defined_ | Force SQLite mode even if `a_mysql` is included. |
| `OMP_AUTH_BUFFER_SIZE` | `512` | Size of query format buffers. |
| `OMP_AUTH_MIN_PASSWORD_INPUT` | `6` | Minimum password length for registration. |
| `OMP_AUTH_AUTO_HANDLE` | _not defined_ | Toggles automations for dialog internal handling. |

## Note
In order for `OMP_AUTH_AUTO_HANDLE` to work properly, it is necessary to call `Auth_LoadUserData` after the player joining the server. Otherwise, it will not work as intended. Also, you can customize the default message value by adding these macros below:

```pawn
#define OMP_AUTH_LOGIN_DIALOG_TITLE     "{FFFFFF}User Login"
#define OMP_AUTH_LOGIN_DIALOG_BODY      "{FFFFFF}Welcome back to our server! Please insert your password below in order to login\n{acacac}(NOTE: You only have %d chances before getting kicked from the server)"
#define OMP_AUTH_REGISTER_DIALOG_TITLE  "{FFFFFF}User Register"
#define OMP_AUTH_REGISTER_DIALOG_BODY   "{FFFFFF}Welcome to our server! Please insert your password below in order to register\n{acacac}(NOTE: The minimum password requirement is %d)"
#define OMP_AUTH_EMPTY_MESSAGE          "{FF0000}ERROR: Invalid input specified, please try again!"
#define OMP_AUTH_FAIL_MESSAGE           "{FF0000}ERROR: Invalid password specified, please try again!"
#define OMP_AUTH_REQ_MESSAGE            "{FF0000}ERROR: Your password is less than the requirement, please try again!"
```

## Function API

All exposed functions are listed below.

### `Auth_Init`
```pawn
bool: Auth_Init({MySQL, DB}: connection,
    const table[]       =   "accounts",
    const idField[]     =   "id",
    const userNameField[] = "Username",
    const passwordField[] = "Password",
    tag = tagof(connection)
)
```
Initializes the authentication system.  
- `connection` – your open MySQL or SQLite handle.  
- `table` – name of the accounts table.  
- `idField`, `userNameField`, `passwordField` – column names.  
- Returns `true` on success, `false` if connection is invalid or table creation fails.  
(The table is created automatically if it doesn’t exist; missing columns are added)

---

### `Auth_LoadUserData`
```pawn
bool:Auth_LoadUserData(playerid)
```
Loads (or reloads) the player’s account data. Call this when the player connects.  
Triggers `OnUserAuthDataLoaded` with the account ID (0 = no account).  
Returns `true` if the query was sent, `false` otherwise.

---

### `Auth_ShowLoginDialog`
```pawn
Auth_ShowLoginDialog(playerid,
    const title[], 
    const body[],
    const button1[], 
    const button2[],
    OPEN_MP_TAGS:...
)
```
Shows a password‑style for login dialog.  
Returns `1` if the dialog was sent, `0` otherwise.


---

### `Auth_ShowRegisterDialog`
```pawn
Auth_ShowRegisterDialog(playerid,
    const title[], const body[],
    const button1[], const button2[],
    OPEN_MP_TAGS: ...
)
```
Shows a password‑style for registration dialog.  
Returns `1` if the dialog was sent, `0` otherwise.

---

### `Auth_IsUserDataLoaded`
```pawn
bool:Auth_IsUserDataLoaded(playerid)
```
Checks whether the player data is loaded.    
Returns `true` if the player’s account data has been fetched from the database, `false` otherwise.

---

### `Auth_IsUserLoggedIn`
```pawn
bool:Auth_IsUserLoggedIn(playerid)
```
Checks whether the player has successfully passed the password verification.  
Returns `true` if the account is logged in, `false` otherwise.

---

### `Auth_GetUserID`
```pawn
bool:Auth_GetUserID(playerid, &uid)
```
Retrieves the account ID of the player.  
Fails if data is not loaded.

---

### `Auth_GetUserName`
```pawn
bool:Auth_GetUserName(playerid, name[], len = sizeof(name))
```
Gets the stored username of the player.  
Fails if data is not loaded.

---

### `Auth_SetUserName`
```pawn
bool:Auth_SetUserName(playerid, const name[], bool: sync = false)
```
Updates the player’s username in the database and in memory.  
If `sync` is `true`, `SetPlayerName` is called to change the in‑game name immediately.  
Returns `true` on success.

---

### `Auth_ResetData`
```pawn
Auth_ResetData(playerid)
```
Clears all cached account data for the player and triggers `OnUserAuthResetData`.  
Useful when kicking a player who refused to log in or after disconnection.

---

## Callbacks (Forwards)

These must be implemented in your gamemode:

- **`OnUserAuthDataLoaded(playerid, uid)`**  
  Called after `Auth_LoadUserData` completes. `uid` = 0 if no account exists.

- **`OnAuthUserRegister(playerid, uid, OMP_AUTH_ERROR:error)`**  
  Called after a registration attempt. Check `error` against the enum below.

- **`OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error)`**  
  Called after a login attempt. `error == OMP_AUTH_NO_ERROR` indicates success.

- **`OnUserAuthResetData(playerid, uid)`**  
  Called when data is reset via `Auth_ResetData`.

## Error Codes

`OMP_AUTH_ERROR` enum values:

| Value | Meaning |
|-------|---------|
| `OMP_AUTH_NO_ERROR` (0) | Operation succeeded |
| `OMP_AUTH_EMPTY_PASSWORD` (1) | Empty password input |
| `OMP_AUTH_MIN_PASSWORD` (2) | Password shorter than `OMP_AUTH_MIN_PASSWORD_INPUT` |
| `OMP_AUTH_WRONG_PASSWORD` (3) | Password did not match stored hash |
| `OMP_AUTH_USER_EXITED` (4) | (Reserved) |
| `OMP_AUTH_FAIL_REGISTER` (5) | Database insertion failed |

## Credits
- **pBlueG & Maddinat0r** for MySQL Plugin
- **SyS** for Bcrypt Plugin
- **Vince0789** for SQL advice

## License

Copyright © 2026 Kanaru Yuuki.  
This project is licensed under the GNU General Public License v3.0 — see the header comment for full terms.
