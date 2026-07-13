#include "VaultSession.h"

namespace ClientWarden {
    VaultSession::VaultSession() {
        
    }

    VaultSession::~VaultSession() {
        wssThread.stop();
        refreshThread.stop();
        connectivityThread.stop();
    }
}