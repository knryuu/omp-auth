#include <open.mp>
#include <a_mysql>

#define OMP_AUTH_USE_SQLITE
#define OMP_AUTH_AUTO_HANDLE

#include "src\omp-auth.inc"

#if defined OMP_AUTH_USE_SQLITE
    new DB:test = DB:0;
#else
    new MySQL:test = MYSQL_INVALID_HANDLE;
#endif

main()
{
    print("Hello @ omp-auth.inc");

#if defined OMP_AUTH_USE_SQLITE
    test = DB_Open("test.db");

    if (test == DB:0)
    {
        print("Can't connect!");
        return;
    }
#else
    test = mysql_connect("localhost", "myuser", "test", "mydb"); 
    
    if (mysql_errno(test))
    {
        print("Your connection is cooked!");
        return;
    }
#endif

    Auth_Init(test);
    return;
}

public OnPlayerConnect(playerid)
{
    Auth_LoadUserData(playerid);
    return 1;
}

#if !defined OMP_AUTH_AUTO_HANDLE
public OnUserAuthDataLoaded(playerid, uid)
{
    if (uid == 0)
    {
        SendClientMessage(playerid, 0xFFFFFFAA, "Your account is not exists in our database!");
        Auth_ShowRegisterDialog(playerid, "{FFFFFF}Register Dialog", "{FFFFFF}Welcome! Please insert password below to yap", "Register", "Exit");
    }
    else
    {
        SendClientMessage(playerid, 0xFFFFFFAA, "Your account exists!");
        Auth_ShowLoginDialog(playerid, "{FFFFFF}Login Dialog", "{FFFFFF}Welcome back! Insert password below to yap", "Login", "Exit");
    }
    return 1;
}

public OnAuthUserRegistered(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_EMPTY_PASSWORD)
    {
        Auth_ShowRegisterDialog(playerid, "{FFFFFF}Register Dialog", "{FF0000}ERROR: Invalid password specified, please try again!\n\n{FFFFFF}Welcome! Insert password below to yap", "Register", "Exit");
        return 1;
    }

    if (error == OMP_AUTH_MIN_PASSWORD)
    {
        Auth_ShowRegisterDialog(playerid, "{FFFFFF}Register Dialog", "{FF0000}ERROR: Password must not be less than "#OMP_AUTH_MIN_PASSWORD_INPUT"!\n\n{FFFFFF}Welcome! Insert password below to yap", "Register", "Exit");
        return 1;
    }

    SendClientMessage(playerid, 0xFFFFFFAA, "User registered (UID: %d)", uid);
    Auth_ShowLoginDialog(playerid, "{FFFFFF}Login Dialog", "{FFFFFF}Welcome back! Insert password below to yap", "Login", "Exit");
    return 1;
}

public OnAuthUserLogin(playerid, uid, OMP_AUTH_ERROR:error)
{
    if (error == OMP_AUTH_EMPTY_PASSWORD)
    {
        Auth_ShowLoginDialog(playerid, "{FFFFFF}Login Dialog", "{FF0000}ERROR: Invalid password specified, please try again!\n\n{FFFFFF}Welcome back! Insert password below to yap", "Login", "Exit");
        return 1;
    }

    if (error == OMP_AUTH_WRONG_PASSWORD)
    {
        Auth_ShowLoginDialog(playerid, "{FFFFFF}Login Dialog", "{FF0000}ERROR: Wrong password, try again!\n\n{FFFFFF}Welcome back! Insert password below to yap", "Login", "Exit");
        return 1;
    }

    SendClientMessage(playerid, 0xFFFFFFAA, "User joined (UID: %d)", uid);
    return 1;
}
#endif