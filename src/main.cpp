#include "sshd.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ssh::sshd server;

    /* initialize the server */
    server.init(NULL);

    return 0;
}