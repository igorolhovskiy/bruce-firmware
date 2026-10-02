#ifndef __TOOL_HELP_H__
#define __TOOL_HELP_H__
#if !defined(LITE_VERSION)

// Per-section "Tool Help" screens: a submenu of the section's tools, each opening
// a scrollable manual page (what it does + how to use it + hints). Registered as
// a "Tool Help" entry in the WiFi, BLE and Detector (Counter-Surveil) menus.
void wifiToolHelp();
void bleToolHelp();
void detectorToolHelp();

#endif
#endif // __TOOL_HELP_H__
