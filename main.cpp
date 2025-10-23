#include <vector>
#include <cstdio>
#include "bob.h"
#include <csignal>
#include <cstdlib>

bool bob_client_stop_flag = false;
static void onSigInt(int) {
    if (!bob_client_stop_flag)
    {
        requestToExitBob();
        bob_client_stop_flag = true;
    }
    else
    {
        printf("Pressed Ctrl+C twice, killing the process...\n");
        exit(3);
    }
}
// Installs a SIGINT handler that prints the summary then exits(130)
void installCtrlCPrinter() {
    std::signal(SIGINT, &onSigInt);
}

int main(int argc, char *argv[]) {
    installCtrlCPrinter();
    try {
        return runBob(argc, argv);
    }
    catch (std::exception &ex) {
        printf("%s", ex.what());
        return -1;
    }
}
