#ifndef HEADER_TcpStateMeter
#define HEADER_TcpStateMeter
/*
htop - linux/TcpStateMeter.h
(C) 2026 Inchan Choi
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "Meter.h"


typedef enum {
   TCP_STATE_METER_ESTABLISHED = 0,
   TCP_STATE_METER_LISTEN = 1,
   TCP_STATE_METER_TIME_WAIT = 2,
   TCP_STATE_METER_CLOSE_WAIT = 3,
   TCP_STATE_METER_OTHER = 4,
   TCP_STATE_METER_ITEMCOUNT = 5, // number of entries in this enum
} TcpStateMeterValues;

extern const MeterClass TcpStateMeter_class;

#endif
