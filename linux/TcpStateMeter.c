/*
htop - linux/TcpStateMeter.c
(C) 2026 Inchan Choi
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "config.h" // IWYU pragma: keep

#include "linux/TcpStateMeter.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "CRT.h"
#include "Macros.h"
#include "Meter.h"
#include "Object.h"
#include "RichString.h"
#include "XUtils.h"
#include "linux/LinuxMachine.h"


/* TCP states as numbered by the Linux kernel (include/net/tcp_states.h).
   Only the states shown separately by this meter are listed here;
   every other valid state is counted as "other". */
enum {
   KERNEL_TCP_ESTABLISHED = 0x01,
   KERNEL_TCP_TIME_WAIT   = 0x06,
   KERNEL_TCP_CLOSE_WAIT  = 0x08,
   KERNEL_TCP_LISTEN      = 0x0A,
   KERNEL_TCP_STATE_LIMIT = 0x0C, // first value that is not a valid state
};

static const int TcpStateMeter_attributes[TCP_STATE_METER_ITEMCOUNT] = {
   [TCP_STATE_METER_ESTABLISHED] = TCP_STATE_ESTABLISHED,
   [TCP_STATE_METER_LISTEN] = TCP_STATE_LISTEN,
   [TCP_STATE_METER_TIME_WAIT] = TCP_STATE_TIME_WAIT,
   [TCP_STATE_METER_CLOSE_WAIT] = TCP_STATE_CLOSE_WAIT,
   [TCP_STATE_METER_OTHER] = TCP_STATE_OTHER,
};

static const char* const TcpStateMeter_labels[TCP_STATE_METER_ITEMCOUNT] = {
   [TCP_STATE_METER_ESTABLISHED] = "est: ",
   [TCP_STATE_METER_LISTEN] = " listen: ",
   [TCP_STATE_METER_TIME_WAIT] = " time_wait: ",
   [TCP_STATE_METER_CLOSE_WAIT] = " close_wait: ",
   [TCP_STATE_METER_OTHER] = " other: ",
};

/* Map a kernel TCP state number to the item of this meter it belongs to */
static TcpStateMeterValues TcpStateMeter_classify(unsigned int state) {
   switch (state) {
      case KERNEL_TCP_ESTABLISHED:
         return TCP_STATE_METER_ESTABLISHED;
      case KERNEL_TCP_LISTEN:
         return TCP_STATE_METER_LISTEN;
      case KERNEL_TCP_TIME_WAIT:
         return TCP_STATE_METER_TIME_WAIT;
      case KERNEL_TCP_CLOSE_WAIT:
         return TCP_STATE_METER_CLOSE_WAIT;
      default:
         return TCP_STATE_METER_OTHER;
   }
}

/* Read one table in the format of /proc/net/tcp and add the number of
   connections in each state to 'values'.
   Returns false if the file could not be opened. */
static bool TcpStateMeter_readTable(const char* path, double* values) {
   FILE* fp = fopen(path, "r");
   if (!fp)
      return false;

   char line[512];

   /* the first line only holds the column names */
   if (!fgets(line, sizeof(line), fp)) {
      fclose(fp);
      return true;
   }

   while (fgets(line, sizeof(line), fp)) {
      unsigned int state;

      /* columns: sl local_address rem_address st ...
         skip the first three columns and read "st" as a hex number */
      if (sscanf(line, "%*s %*s %*s %x", &state) != 1)
         continue;

      if (state == 0 || state >= KERNEL_TCP_STATE_LIMIT)
         continue;

      values[TcpStateMeter_classify(state)] += 1;
   }

   fclose(fp);
   return true;
}

static void TcpStateMeter_updateValues(Meter* this) {
   for (size_t i = 0; i < TCP_STATE_METER_ITEMCOUNT; i++)
      this->values[i] = 0;

   bool haveIPv4 = TcpStateMeter_readTable(PROCDIR "/net/tcp", this->values);
   bool haveIPv6 = TcpStateMeter_readTable(PROCDIR "/net/tcp6", this->values);

   if (!haveIPv4 && !haveIPv6) {
      for (size_t i = 0; i < TCP_STATE_METER_ITEMCOUNT; i++)
         this->values[i] = NAN;

      xSnprintf(this->txtBuffer, sizeof(this->txtBuffer), "unavailable");
      return;
   }

   xSnprintf(this->txtBuffer, sizeof(this->txtBuffer), "%.0f/%.0f/%.0f",
             this->values[TCP_STATE_METER_ESTABLISHED],
             this->values[TCP_STATE_METER_LISTEN],
             this->values[TCP_STATE_METER_TIME_WAIT]);
}

static void TcpStateMeter_display(const Object* cast, RichString* out) {
   const Meter* this = (const Meter*)cast;

   if (!isNonnegative(this->values[TCP_STATE_METER_ESTABLISHED])) {
      RichString_writeAscii(out, CRT_colors[METER_VALUE_ERROR], "unavailable");
      return;
   }

   char buffer[16];

   for (size_t i = 0; i < TCP_STATE_METER_ITEMCOUNT; i++) {
      RichString_appendAscii(out, CRT_colors[METER_TEXT], TcpStateMeter_labels[i]);

      int len = xSnprintf(buffer, sizeof(buffer), "%.0f", this->values[i]);
      RichString_appendnAscii(out, CRT_colors[TcpStateMeter_attributes[i]], buffer, len);
   }
}

const MeterClass TcpStateMeter_class = {
   .super = {
      .extends = Class(Meter),
      .delete = Meter_delete,
      .display = TcpStateMeter_display,
   },
   .updateValues = TcpStateMeter_updateValues,
   .defaultMode = TEXT_METERMODE,
   .supportedModes = METERMODE_DEFAULT_SUPPORTED,
   .maxItems = TCP_STATE_METER_ITEMCOUNT,
   .isPercentChart = false,
   .total = 16.0,
   .attributes = TcpStateMeter_attributes,
   .name = "TcpState",
   .uiName = "TCP connections",
   .caption = "TCP: ",
   .description = "Number of TCP connections by state, read from /proc/net/tcp and /proc/net/tcp6"
};
