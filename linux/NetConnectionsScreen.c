/*
htop - linux/NetConnectionsScreen.c
(C) 2026 Inchan Choi
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "config.h" // IWYU pragma: keep

#include "linux/NetConnectionsScreen.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "Macros.h"
#include "Panel.h"
#include "ProvideCurses.h"
#include "Vector.h"
#include "XUtils.h"
#include "linux/LinuxMachine.h"


/* A socket found in /proc/<pid>/fd: which descriptor points to which socket inode */
typedef struct SocketRef_ {
   int fd;
   unsigned long inode;
} SocketRef;

/* One row of the screen */
typedef struct NetConnection_ {
   int fd;
   const char* proto;
   char local[64];
   char remote[64];
   const char* state;
} NetConnection;

typedef struct NetConnectionList_ {
   NetConnection* items;
   size_t count;
   size_t capacity;
} NetConnectionList;

/* Kernel socket tables, read from /proc/<pid>/net/ so that the
   network namespace of the inspected process is used */
typedef struct NetTable_ {
   const char* file;
   const char* proto;
   int family;
   bool isTcp;
} NetTable;

static const NetTable NetConnectionsScreen_tables[] = {
   { "tcp",  "TCP",  AF_INET,  true  },
   { "tcp6", "TCP6", AF_INET6, true  },
   { "udp",  "UDP",  AF_INET,  false },
   { "udp6", "UDP6", AF_INET6, false },
};

/* TCP states as numbered in the kernel (include/net/tcp_states.h) */
static const char* const NetConnectionsScreen_tcpStates[] = {
   [0x01] = "ESTABLISHED",
   [0x02] = "SYN_SENT",
   [0x03] = "SYN_RECV",
   [0x04] = "FIN_WAIT1",
   [0x05] = "FIN_WAIT2",
   [0x06] = "TIME_WAIT",
   [0x07] = "CLOSE",
   [0x08] = "CLOSE_WAIT",
   [0x09] = "LAST_ACK",
   [0x0A] = "LISTEN",
   [0x0B] = "CLOSING",
};

static const char* NetConnectionsScreen_stateName(bool isTcp, unsigned int state) {
   if (!isTcp) {
      /* UDP has no handshake: the kernel only marks connected (01) or unconnected (07) sockets */
      return state == 0x01 ? "ESTABLISHED" : "UNCONN";
   }

   if (state < ARRAYSIZE(NetConnectionsScreen_tcpStates) && NetConnectionsScreen_tcpStates[state])
      return NetConnectionsScreen_tcpStates[state];

   return "UNKNOWN";
}

NetConnectionsScreen* NetConnectionsScreen_new(const Process* process) {
   NetConnectionsScreen* this = xCalloc(1, sizeof(NetConnectionsScreen));
   Object_setClass(this, Class(NetConnectionsScreen));
   if (Process_isThread(process)) {
      this->pid = Process_getThreadGroup(process);
   } else {
      this->pid = Process_getPid(process);
   }
   return (NetConnectionsScreen*) InfoScreen_init(&this->super, process, NULL, LINES - 2, "   FD PROTO LOCAL ADDRESS  REMOTE ADDRESS  STATE");
}

void NetConnectionsScreen_delete(Object* this) {
   free(InfoScreen_done((InfoScreen*)this));
}

static void NetConnectionsScreen_draw(InfoScreen* this) {
   InfoScreen_drawTitled(this, "Network connections of process %d - %s", ((NetConnectionsScreen*)this)->pid, Process_getCommand(this->process));
}

static int NetConnectionsScreen_compareInode(const void* a, const void* b) {
   unsigned long ia = ((const SocketRef*)a)->inode;
   unsigned long ib = ((const SocketRef*)b)->inode;
   return (ia > ib) - (ia < ib);
}

/*
 * Step 1: list /proc/<pid>/fd and keep every descriptor whose link
 * target looks like "socket:[12345]". Returns 0 or an errno value.
 */
static int NetConnectionsScreen_collectSockets(pid_t pid, SocketRef** refs, size_t* count) {
   char path[64];
   xSnprintf(path, sizeof(path), PROCDIR "/%d/fd", (int)pid);

   *refs = NULL;
   *count = 0;

   DIR* dir = opendir(path);
   if (!dir)
      return errno ? errno : EIO;

   size_t capacity = 0;
   const struct dirent* entry;
   while ((entry = readdir(dir)) != NULL) {
      if (entry->d_name[0] == '.')
         continue;

      char target[64];
      ssize_t len = readlinkat(dirfd(dir), entry->d_name, target, sizeof(target) - 1);
      if (len <= 0)
         continue;
      target[len] = '\0';

      unsigned long inode;
      if (sscanf(target, "socket:[%lu]", &inode) != 1)
         continue;

      if (*count == capacity) {
         capacity = capacity ? capacity * 2 : 16;
         *refs = xReallocArray(*refs, capacity, sizeof(SocketRef));
      }
      (*refs)[*count].fd = atoi(entry->d_name);
      (*refs)[*count].inode = inode;
      (*count)++;
   }
   closedir(dir);

   /* sorted by inode so that the table lookup below can use bsearch */
   if (*count > 1)
      qsort(*refs, *count, sizeof(SocketRef), NetConnectionsScreen_compareInode);

   return 0;
}

/*
 * Turn the hex address of /proc/net/{tcp,udp}[6] into text.
 * The kernel prints each 32 bit word as it is stored in memory,
 * so reading it back as a native integer restores network byte order.
 */
static bool NetConnectionsScreen_formatAddress(int family, const char* hex, unsigned int port, char* out, size_t outSize) {
   char text[INET6_ADDRSTRLEN];
   size_t words = (family == AF_INET) ? 1 : 4;

   if (strlen(hex) != words * 8)
      return false;

   uint32_t raw[4] = {0};
   for (size_t i = 0; i < words; i++) {
      char chunk[9];
      memcpy(chunk, hex + i * 8, 8);
      chunk[8] = '\0';
      raw[i] = (uint32_t) strtoul(chunk, NULL, 16);
   }

   if (family == AF_INET) {
      struct in_addr addr;
      addr.s_addr = raw[0];
      if (!inet_ntop(AF_INET, &addr, text, sizeof(text)))
         return false;
   } else {
      struct in6_addr addr;
      memcpy(&addr, raw, sizeof(addr));
      if (!inet_ntop(AF_INET6, &addr, text, sizeof(text)))
         return false;
   }

   const char* open = (family == AF_INET6) ? "[" : "";
   const char* close = (family == AF_INET6) ? "]" : "";
   if (port == 0) {
      xSnprintf(out, outSize, "%s%s%s:*", open, text, close);
   } else {
      xSnprintf(out, outSize, "%s%s%s:%u", open, text, close, port);
   }
   return true;
}

static NetConnection* NetConnectionList_add(NetConnectionList* list) {
   if (list->count == list->capacity) {
      list->capacity = list->capacity ? list->capacity * 2 : 16;
      list->items = xReallocArray(list->items, list->capacity, sizeof(NetConnection));
   }
   NetConnection* conn = &list->items[list->count++];
   memset(conn, 0, sizeof(*conn));
   return conn;
}

/*
 * Step 2: read one kernel socket table and keep the rows whose
 * inode belongs to the process.
 *
 *   sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
 *   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0       0  3045
 */
static void NetConnectionsScreen_readTable(pid_t pid, const NetTable* table, const SocketRef* refs, size_t refCount, NetConnectionList* list) {
   char path[64];
   xSnprintf(path, sizeof(path), PROCDIR "/%d/net/%s", (int)pid, table->file);

   FILE* fp = fopen(path, "r");
   if (!fp)
      return;

   char line[512];
   if (!fgets(line, sizeof(line), fp)) { /* skip the header line */
      fclose(fp);
      return;
   }

   while (fgets(line, sizeof(line), fp)) {
      char localHex[33];
      char remoteHex[33];
      unsigned int localPort;
      unsigned int remotePort;
      unsigned int state;
      unsigned long inode;

      int n = sscanf(line, "%*s %32[0-9A-Fa-f]:%x %32[0-9A-Fa-f]:%x %x %*s %*s %*s %*s %*s %lu",
                     localHex, &localPort, remoteHex, &remotePort, &state, &inode);
      if (n != 6 || inode == 0)
         continue;

      const SocketRef key = { .fd = 0, .inode = inode };
      const SocketRef* ref = bsearch(&key, refs, refCount, sizeof(SocketRef), NetConnectionsScreen_compareInode);
      if (!ref)
         continue;

      NetConnection* conn = NetConnectionList_add(list);
      conn->fd = ref->fd;
      conn->proto = table->proto;
      conn->state = NetConnectionsScreen_stateName(table->isTcp, state);
      if (!NetConnectionsScreen_formatAddress(table->family, localHex, localPort, conn->local, sizeof(conn->local)))
         xSnprintf(conn->local, sizeof(conn->local), "?");
      if (!NetConnectionsScreen_formatAddress(table->family, remoteHex, remotePort, conn->remote, sizeof(conn->remote)))
         xSnprintf(conn->remote, sizeof(conn->remote), "?");
   }

   fclose(fp);
}

static void NetConnectionsScreen_scan(InfoScreen* super) {
   const NetConnectionsScreen* this = (const NetConnectionsScreen*)super;
   Panel* panel = super->display;
   int idx = Panel_getSelectedIndex(panel);
   Panel_prune(panel);

   SocketRef* refs = NULL;
   size_t refCount = 0;
   int err = NetConnectionsScreen_collectSockets(this->pid, &refs, &refCount);

   if (err == EACCES || err == EPERM) {
      InfoScreen_addLine(super, "Permission denied. Run htop as root to see the connections of this process.");
   } else if (err != 0) {
      InfoScreen_addLine(super, "Could not read the open files of this process.");
   } else {
      NetConnectionList list = { .items = NULL, .count = 0, .capacity = 0 };

      if (refCount > 0) {
         for (size_t i = 0; i < ARRAYSIZE(NetConnectionsScreen_tables); i++) {
            NetConnectionsScreen_readTable(this->pid, &NetConnectionsScreen_tables[i], refs, refCount, &list);
         }
      }

      /* column widths follow the longest address, IPv6 ones can be long */
      int localWidth = (int)strlen("LOCAL ADDRESS");
      int remoteWidth = (int)strlen("REMOTE ADDRESS");
      for (size_t i = 0; i < list.count; i++) {
         localWidth = MAXIMUM(localWidth, (int)strlen(list.items[i].local));
         remoteWidth = MAXIMUM(remoteWidth, (int)strlen(list.items[i].remote));
      }

      char header[256];
      xSnprintf(header, sizeof(header), "%5s %-5s %-*s %-*s %s",
                "FD", "PROTO", localWidth, "LOCAL ADDRESS", remoteWidth, "REMOTE ADDRESS", "STATE");
      Panel_setHeader(panel, header);

      if (list.count == 0) {
         InfoScreen_addLine(super, "No TCP or UDP sockets are open in this process.");
      }

      for (size_t i = 0; i < list.count; i++) {
         const NetConnection* conn = &list.items[i];
         char* entry = NULL;
         xAsprintf(&entry, "%5d %-5s %-*s %-*s %s",
                   conn->fd, conn->proto,
                   localWidth, conn->local,
                   remoteWidth, conn->remote,
                   conn->state);
         InfoScreen_addLine(super, entry);
         free(entry);
      }

      free(list.items);
   }

   free(refs);
   Vector_insertionSort(super->lines);
   Vector_insertionSort(panel->items);
   Panel_setSelected(panel, idx);
}

const InfoScreenClass NetConnectionsScreen_class = {
   .super = {
      .extends = Class(Object),
      .delete = NetConnectionsScreen_delete
   },
   .scan = NetConnectionsScreen_scan,
   .draw = NetConnectionsScreen_draw
};
