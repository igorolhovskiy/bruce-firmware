#include "ble_commands.h"
#include <globals.h>
#if !defined(LITE_VERSION)
#include "modules/ble/led_badge.h"
#endif

static uint32_t ledBadgeCallback(cmd *c) {
#if !defined(LITE_VERSION)
    Command cmd(c);

    const int argc = cmd.countArgs();
    if (argc <= 0) {
        serialDevice->println("usage: ledbadge test | ledbadge <text>");
        return true;
    }

    String first = cmd.getArgument(0).getValue();
    first.trim();
    if (first.equalsIgnoreCase("test")) {
        ledBadgeSelfTest();
        return true;
    }
    if (first.equalsIgnoreCase("scan")) {
        ledBadgeScanDump();
        return true;
    }

    // Rejoin all tokens as the message text (boundless split on spaces).
    String text = "";
    for (int i = 0; i < argc; ++i) {
        if (i) text += " ";
        text += cmd.getArgument(i).getValue();
    }
    serialDevice->println("[LEDBadge] Sending: " + text);
    bool ok = ledBadgeSendText(text);
    serialDevice->println(ok ? "[LEDBadge] OK" : "[LEDBadge] FAILED");
    return ok;
#else
    return true;
#endif
}

void createBleCommands(SimpleCLI *cli) {
#if !defined(LITE_VERSION)
    cli->addBoundlessCmd("ledbadge", ledBadgeCallback);
#endif
}
