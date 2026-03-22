/* AethroSync — src/ui.c — colour UI state */
#define _GNU_SOURCE
#include "../include/mpcp.h"

/* Single definition of g_ui_colour (all TUs get extern from mpcp.h) */
bool g_ui_colour = false;
