
#include <open.mp>
#include <a_mysql>

//#define OMP_AUTH_USE_SQLITE
#include "src\omp-auth.inc"

new MySQL:test = MYSQL_INVALID_HANDLE;

main()
{
    print("Hello @ omp-auth.inc");

    test = mysql_connect("localhost", "myuser", "test", "mydb"); 
    
    if (mysql_errno(test))
    {
        print("Your connection is shit!");
        return;
    }

    Auth_Init(test);
    return;
}

public OnPlayerConnect(playerid)
{
    Auth_LoadUserData(playerid);
    return 1;
}

public OnUserAuthDataLoaded(playerid, uid)
{
    if (!uid)
    {
        SendClientMessage(playerid, 0xFFFFFFAA, "Your account is not exists in our database!");
        Auth_ShowRegisterDialog(playerid, "{FFFFFF}Register Dialog", "{FFFFFF}Welcome! Please insert password below to yap", "Login", "Exit");
    }
    else
    {
        SendClientMessage(playerid, 0xFFFFFFAA, "Your account exists!");
    }
    return 1;
}

public OnAuthUserRegistered(playerid, uid)
{
    SendClientMessage(playerid, 0xFFFFFFAA, "User registered (UID: %d)", uid);
    return 1;
}