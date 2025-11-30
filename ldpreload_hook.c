#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// Hook getenv - skryje LD_PRELOAD premennú
char *getenv(const char *name) {
    static char *(*real_getenv)(const char *) = NULL;
    if (!real_getenv) {
        real_getenv = dlsym(RTLD_NEXT, "getenv");
    }
    
    // Ak sa pýta na LD_PRELOAD, vráť NULL (akoby nebola nastavená)
    if (name && strcmp(name, "LD_PRELOAD") == 0) {
        return NULL;
    }
    
    return real_getenv(name);
}
