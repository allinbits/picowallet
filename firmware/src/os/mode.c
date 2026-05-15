#include "os/mode.h"

// Defaults to TMKMS (CDC). Boot replaces this with the operator's choice.
os_mode_t os_current_mode = OS_MODE_TMKMS;

const char *os_mode_name(os_mode_t m) {
    switch (m) {
        case OS_MODE_PRIVVAL: return "PrivVal";
        case OS_MODE_TMKMS:   return "TMKMS";
    }
    return "unknown";
}
