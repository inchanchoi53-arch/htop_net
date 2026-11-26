#ifndef HEADER_NetConnectionsScreen
#define HEADER_NetConnectionsScreen
/*
htop - linux/NetConnectionsScreen.h
(C) 2026 Inchan Choi
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include <sys/types.h>

#include "InfoScreen.h"
#include "Object.h"
#include "Process.h"


typedef struct NetConnectionsScreen_ {
   InfoScreen super;
   pid_t pid;
} NetConnectionsScreen;

extern const InfoScreenClass NetConnectionsScreen_class;

NetConnectionsScreen* NetConnectionsScreen_new(const Process* process);

void NetConnectionsScreen_delete(Object* this);

#endif
