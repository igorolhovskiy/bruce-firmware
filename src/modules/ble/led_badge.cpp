/**
 * @file led_badge.cpp
 * @brief Send text to a Bluetooth "LED name badge" (44x11, LSLED/VBLAB).
 *
 * Protocol + 8x11 font ported from FOSSASIA BadgeMagic (AGPL):
 *   DataToByteArrayConverter.kt / Converters.kt / GattClient.kt / Badges.kt
 *   https://github.com/fossasia/badgemagic-app
 * Brightness header byte from led-name-badge-ls32.
 */
#if !defined(LITE_VERSION)
#include "led_badge.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <NimBLEDevice.h>
#include <globals.h>

#if __has_include(<NimBLEExtAdvertising.h>)
#define NIMBLE_V2_PLUS 1
#endif

// ---------------------------------------------------------------------------
// Font: each glyph is 8 (wide) x 11 (tall), stored as 11 bytes (one per row,
// bit 7 = leftmost column). Hex strings taken verbatim from BadgeMagic CHAR_CODES.
// ASCII printable subset only (the on-screen keyboard cannot produce the
// unicode symbols in the original table).
// ---------------------------------------------------------------------------
struct Glyph {
    char c;
    const char *hex; // 22 hex chars == 11 bytes
};

static const Glyph FONT[] = {
    {'0', "007CC6CEDEF6E6C6C67C00"}, {'1', "0018387818181818187E00"},
    {'2', "007CC6060C183060C6FE00"}, {'3', "007CC606063C0606C67C00"},
    {'4', "000C1C3C6CCCFE0C0C1E00"}, {'5', "00FEC0C0FC060606C67C00"},
    {'6', "007CC6C0C0FCC6C6C67C00"}, {'7', "00FEC6060C183030303000"},
    {'8', "007CC6C6C67CC6C6C67C00"}, {'9', "007CC6C6C67E0606C67C00"},
    {'#', "006C6CFE6C6CFE6C6C0000"}, {'&', "00386C6C3876DCCCCC7600"},
    {'_', "00000000000000000000FF"}, {'-', "0000000000FE0000000000"},
    {'?', "007CC6C60C181800181800"}, {'@', "00003C429DA5ADB6403C00"},
    {'(', "000C183030303030180C00"}, {')', "0030180C0C0C0C0C183000"},
    {'=', "0000007E00007E00000000"}, {'+', "00000018187E1818000000"},
    {'!', "00183C3C3C181800181800"}, {'\'', "1818081000000000000000"},
    {':', "0000001818000018180000"}, {'%', "006092966C106CD2920C00"},
    {'/', "000002060C183060C08000"}, {'"', "6666222200000000000000"},
    {' ', "0000000000000000000000"}, {'*', "000000663CFF3C66000000"},
    {',', "0000000000000030301020"}, {'.', "0000000000000000303000"},
    {'~', "0076DC0000000000000000"}, {'[', "003C303030303030303C00"},
    {']', "003C0C0C0C0C0C0C0C3C00"}, {'{', "000E181818701818180E00"},
    {'}', "00701818180E1818187000"}, {'<', "00060C18306030180C0600"},
    {'>', "006030180C060C18306000"}, {'^', "386CC60000000000000000"},
    {'`', "1818100800000000000000"}, {';', "0000001818000018180810"},
    {'\\', "0080C06030180C06020000"}, {'|', "0018181818001818181800"},
    {'$', "00287EA8A87C2A2AFC2800"},
    {'a', "00000000780C7CCCCC7600"}, {'b', "00E060607C666666667C00"},
    {'c', "000000007CC6C0C0C67C00"}, {'d', "001C0C0C7CCCCCCCCC7600"},
    {'e', "000000007CC6FEC0C67C00"}, {'f', "001C363078303030307800"},
    {'g', "00000076CCCCCC7C0CCC78"}, {'h', "00E060606C76666666E600"},
    {'i', "0018180038181818183C00"}, {'j', "0C0C001C0C0C0C0CCCCC78"},
    {'k', "00E06060666C78786CE600"}, {'l', "0038181818181818183C00"},
    {'m', "00000000ECFED6D6D6C600"}, {'n', "00000000DC666666666600"},
    {'o', "000000007CC6C6C6C67C00"}, {'p', "000000DC6666667C6060F0"},
    {'q', "0000007CCCCCCC7C0C0C1E"}, {'r', "00000000DE76606060F000"},
    {'s', "000000007CC6701CC67C00"}, {'t', "00103030FC303030341800"},
    {'u', "00000000CCCCCCCCCC7600"}, {'v', "00000000C6C6C66C381000"},
    {'w', "00000000C6D6D6D6FE6C00"}, {'x', "00000000C66C38386CC600"},
    {'y', "000000C6C6C6C67E060CF8"}, {'z', "00000000FE8C183062FE00"},
    {'A', "00386CC6C6FEC6C6C6C600"}, {'B', "00FC6666667C666666FC00"},
    {'C', "007CC6C6C0C0C0C6C67C00"}, {'D', "00FC66666666666666FC00"},
    {'E', "00FE66626878686266FE00"}, {'F', "00FE66626878686060F000"},
    {'G', "007CC6C6C0C0CEC6C67E00"}, {'H', "00C6C6C6C6FEC6C6C6C600"},
    {'I', "003C181818181818183C00"}, {'J', "001E0C0C0C0C0CCCCC7800"},
    {'K', "00E6666C6C786C6C66E600"}, {'L', "00F060606060606266FE00"},
    {'M', "0082C6EEFED6C6C6C6C600"}, {'N', "0086C6E6F6DECEC6C6C600"},
    {'O', "007CC6C6C6C6C6C6C67C00"}, {'P', "00FC6666667C606060F000"},
    {'Q', "007CC6C6C6C6C6D6DE7C06"}, {'R', "00FC6666667C6C6666E600"},
    {'S', "007CC6C660380CC6C67C00"}, {'T', "007E7E5A18181818183C00"},
    {'U', "00C6C6C6C6C6C6C6C67C00"}, {'V', "00C6C6C6C6C6C66C381000"},
    {'W', "00C6C6C6C6D6FEEEC68200"}, {'X', "00C6C66C7C387C6CC6C600"},
    {'Y', "00666666663C1818183C00"}, {'Z', "00FEC6860C183062C6FE00"},
};
static const size_t FONT_COUNT = sizeof(FONT) / sizeof(FONT[0]);

// Badge GATT identifiers (BadgeMagic Badges.kt).
static NimBLEUUID SVC_LSLED("0000fee0-0000-1000-8000-00805f9b34fb");
static NimBLEUUID CHR_LSLED("0000fee1-0000-1000-8000-00805f9b34fb");
static NimBLEUUID SVC_VBLAB("0000fff0-0000-1000-8000-00805f9b34fb");
static NimBLEUUID CHR_VBLAB("0000fff1-0000-1000-8000-00805f9b34fb");

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static const char *glyphFor(char c) {
    for (size_t i = 0; i < FONT_COUNT; ++i)
        if (FONT[i].c == c) return FONT[i].hex;
    return nullptr;
}

// Append the 11 glyph bytes for each renderable char; returns block count.
static uint16_t appendGlyphs(const String &text, std::vector<uint8_t> &out) {
    uint16_t blocks = 0;
    for (size_t i = 0; i < text.length(); ++i) {
        const char *hex = glyphFor(text[i]);
        if (!hex) {
            Serial.printf("[LEDBadge] skipping unsupported char 0x%02X\n", (uint8_t)text[i]);
            continue;
        }
        for (int b = 0; b < 11; ++b) out.push_back((hexVal(hex[b * 2]) << 4) | hexVal(hex[b * 2 + 1]));
        blocks++;
    }
    return blocks;
}

std::vector<uint8_t> buildBadgePacket(const std::vector<LedBadgeMessage> &messages, uint8_t brightness) {
    std::vector<uint8_t> out;
    size_t n = messages.size();
    if (n > 8) n = 8;

    // Pre-render glyphs so we know each message's block count for the size field.
    std::vector<std::vector<uint8_t>> glyphs(n);
    std::vector<uint16_t> sizes(n, 0);
    for (size_t i = 0; i < n; ++i) sizes[i] = appendGlyphs(messages[i].text, glyphs[i]);

    // ---- 64-byte header ----
    out.push_back(0x77);
    out.push_back(0x61);
    out.push_back(0x6E);
    out.push_back(0x67);          // "wang"
    out.push_back(0x00);          // byte 4
    out.push_back(brightness);    // byte 5: brightness (0x00 = full = BadgeMagic default)

    uint8_t flash = 0, marquee = 0;
    for (size_t i = 0; i < n; ++i) {
        if (messages[i].flash) flash |= (1 << i);
        if (messages[i].marquee) marquee |= (1 << i);
    }
    out.push_back(flash);   // byte 6
    out.push_back(marquee); // byte 7

    for (size_t i = 0; i < 8; ++i) { // bytes 8..15: (speed-1)<<4 | mode
        if (i < n) {
            uint8_t sp = messages[i].speed;
            if (sp < 1) sp = 1;
            if (sp > 8) sp = 8;
            out.push_back((uint8_t)(((sp - 1) & 0x07) << 4) | ((uint8_t)messages[i].mode & 0x0F));
        } else out.push_back(0x00);
    }

    for (size_t i = 0; i < 8; ++i) { // bytes 16..31: size (blocks) big-endian per message
        uint16_t s = (i < n) ? sizes[i] : 0;
        out.push_back((s >> 8) & 0xFF);
        out.push_back(s & 0xFF);
    }

    for (int i = 0; i < 6; ++i) out.push_back(0x00); // bytes 32..37

    // bytes 38..43: timestamp (year&0xFF, month, day, hour, min, sec). Fixed valid
    // date; the badge only uses this for its own clock display.
    out.push_back(0x18);
    out.push_back(0x01);
    out.push_back(0x01);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);

    for (int i = 0; i < 4; ++i) out.push_back(0x00);  // bytes 44..47
    for (int i = 0; i < 16; ++i) out.push_back(0x00); // bytes 48..63

    // ---- message glyph data ----
    for (size_t i = 0; i < n; ++i)
        out.insert(out.end(), glyphs[i].begin(), glyphs[i].end());

    // ---- zero-pad to a 16-byte boundary (always adds a trailing block, like BadgeMagic) ----
    size_t padded = ((out.size() / 16) + 1) * 16;
    out.resize(padded, 0x00);
    return out;
}

bool sendBadgePacket(const std::vector<uint8_t> &packet) {
    if (packet.empty()) return false;

    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEScan *scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(99);

    displayTextLine("Scanning badge...");
    Serial.println("[LEDBadge] Scanning for badge (fee0/fff0)...");

#ifdef NIMBLE_V2_PLUS
    NimBLEScanResults results = scan->getResults(5 * 1000, false);
#else
    NimBLEScanResults results = scan->start(5, false);
#endif

    NimBLEAddress addr;
    bool found = false;
    for (int i = 0; i < results.getCount() && !found; ++i) {
#ifdef NIMBLE_V2_PLUS
        const NimBLEAdvertisedDevice *adv = results.getDevice(i);
        String name = String(adv->getName().c_str());
        bool match = adv->isAdvertisingService(SVC_LSLED) || adv->isAdvertisingService(SVC_VBLAB);
        NimBLEAddress a = adv->getAddress();
#else
        NimBLEAdvertisedDevice adv = results.getDevice(i);
        String name = String(adv.getName().c_str());
        bool match = adv.isAdvertisingService(SVC_LSLED) || adv.isAdvertisingService(SVC_VBLAB);
        NimBLEAddress a = adv.getAddress();
#endif
        name.toUpperCase();
        if (match || name.indexOf("LSLED") >= 0 || name.indexOf("LS32") >= 0) {
            addr = a;
            found = true;
        }
    }
    scan->stop();
    scan->clearResults();

    if (!found) {
        Serial.println("[LEDBadge] No badge found.");
        displayError("Badge not found", true);
        return false;
    }

    Serial.printf("[LEDBadge] Connecting to %s...\n", addr.toString().c_str());
    displayTextLine("Connecting...");
    NimBLEClient *client = NimBLEDevice::createClient();
#ifdef NIMBLE_V2_PLUS
    client->setConnectTimeout(10 * 1000); // NimBLE 2.x: milliseconds
#else
    client->setConnectTimeout(10); // NimBLE 1.x: seconds
#endif

    bool ok = false;
    do {
        bool connected = false;
        for (int attempt = 0; attempt < 3 && !connected; ++attempt) {
            if (attempt) {
                Serial.printf("[LEDBadge] Connect retry %d...\n", attempt + 1);
                delay(500);
            }
            connected = client->connect(addr);
        }
        if (!connected) {
            Serial.println("[LEDBadge] Connect failed.");
            break;
        }
        if (!client->discoverAttributes()) {
            Serial.println("[LEDBadge] Attribute discovery failed.");
            break;
        }

        NimBLEUUID chrUuid = CHR_LSLED;
        NimBLERemoteService *svc = client->getService(SVC_LSLED);
        if (!svc) {
            svc = client->getService(SVC_VBLAB);
            chrUuid = CHR_VBLAB;
        }
        if (!svc) {
            Serial.println("[LEDBadge] Badge service not found.");
            break;
        }
        NimBLERemoteCharacteristic *chr = svc->getCharacteristic(chrUuid);
        if (!chr || !(chr->canWrite() || chr->canWriteNoResponse())) {
            Serial.println("[LEDBadge] Write characteristic not usable.");
            break;
        }
        bool response = chr->canWrite();

        size_t total = packet.size() / 16;
        Serial.printf("[LEDBadge] Writing %u chunks (%u bytes)...\n", (unsigned)total, (unsigned)packet.size());
        ok = true;
        for (size_t c = 0; c < total; ++c) {
            if (!chr->writeValue(packet.data() + c * 16, 16, response)) {
                Serial.printf("[LEDBadge] Write %u/%u failed.\n", (unsigned)(c + 1), (unsigned)total);
                ok = false;
                break;
            }
            displayTextLine("Writing " + String((int)(c + 1)) + "/" + String((int)total));
            delay(40);
        }
    } while (false);

    if (client->isConnected()) client->disconnect();
    NimBLEDevice::deleteClient(client);

    Serial.println(ok ? "[LEDBadge] Done." : "[LEDBadge] Send failed.");
    return ok;
}

// ---------------------------------------------------------------------------
// Serial helpers
// ---------------------------------------------------------------------------
bool ledBadgeSendText(const String &text) {
    LedBadgeMessage m;
    m.text = text;
    std::vector<LedBadgeMessage> msgs = {m};
    return sendBadgePacket(buildBadgePacket(msgs));
}

void ledBadgeScanDump() {
    if (!NimBLEDevice::isInitialized()) NimBLEDevice::init("");
    NimBLEScan *scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(99);

    Serial.println("[LEDBadge] Scanning 6s, dumping all devices...");
#ifdef NIMBLE_V2_PLUS
    NimBLEScanResults results = scan->getResults(6 * 1000, false);
#else
    NimBLEScanResults results = scan->start(6, false);
#endif
    Serial.printf("[LEDBadge] %d device(s) found:\n", results.getCount());
    for (int i = 0; i < results.getCount(); ++i) {
#ifdef NIMBLE_V2_PLUS
        const NimBLEAdvertisedDevice *adv = results.getDevice(i);
        String name = String(adv->getName().c_str());
        String addr = String(adv->getAddress().toString().c_str());
        int rssi = adv->getRSSI();
        int nUuids = adv->getServiceUUIDCount();
        String svcs = "";
        for (int u = 0; u < nUuids; ++u) svcs += String(adv->getServiceUUID(u).toString().c_str()) + " ";
#else
        NimBLEAdvertisedDevice adv = results.getDevice(i);
        String name = String(adv.getName().c_str());
        String addr = String(adv.getAddress().toString().c_str());
        int rssi = adv.getRSSI();
        int nUuids = adv.getServiceUUIDCount();
        String svcs = "";
        for (int u = 0; u < nUuids; ++u) svcs += String(adv.getServiceUUID(u).toString().c_str()) + " ";
#endif
        Serial.printf(
            "  [%2d] %-24s rssi=%-4d name=\"%s\" svc=[ %s]\n",
            i,
            addr.c_str(),
            rssi,
            name.c_str(),
            svcs.c_str()
        );
    }
    scan->clearResults();
    Serial.println("[LEDBadge] Scan done.");
}

void ledBadgeSelfTest() {
    LedBadgeMessage m;
    m.text = "Hello";
    std::vector<LedBadgeMessage> msgs = {m};
    std::vector<uint8_t> pkt = buildBadgePacket(msgs);

    Serial.println("[LEDBadge] Self-test packet for \"Hello\":");
    for (size_t i = 0; i < pkt.size(); ++i) {
        Serial.printf("%02X", pkt[i]);
        if ((i % 16) == 15) Serial.println();
    }
    if (pkt.size() % 16) Serial.println();

    bool magic = pkt.size() >= 4 && pkt[0] == 0x77 && pkt[1] == 0x61 && pkt[2] == 0x6E && pkt[3] == 0x67;
    uint16_t size0 = ((uint16_t)pkt[16] << 8) | pkt[17];
    Serial.printf(
        "[LEDBadge] magic=%s size0=%u (expect 5) len=%u aligned=%s\n",
        magic ? "OK" : "BAD",
        size0,
        (unsigned)pkt.size(),
        (pkt.size() % 16 == 0) ? "OK" : "BAD"
    );
}

// ---------------------------------------------------------------------------
// On-device UI
// ---------------------------------------------------------------------------
static String modeName(BadgeMode m) {
    switch (m) {
        case BadgeMode::LEFT: return "Left";
        case BadgeMode::RIGHT: return "Right";
        case BadgeMode::UP: return "Up";
        case BadgeMode::DOWN: return "Down";
        case BadgeMode::FIXED: return "Fixed";
        case BadgeMode::SNOWFLAKE: return "Snowflake";
        case BadgeMode::PICTURE: return "Picture";
        case BadgeMode::ANIMATION: return "Animation";
        case BadgeMode::LASER: return "Laser";
    }
    return "?";
}

static String brightName(uint8_t b) {
    switch (b) {
        case BADGE_BRIGHTNESS_100: return "100%";
        case BADGE_BRIGHTNESS_75: return "75%";
        case BADGE_BRIGHTNESS_50: return "50%";
        case BADGE_BRIGHTNESS_25: return "25%";
    }
    return "100%";
}

static void chooseMode(LedBadgeMessage &m) {
    std::vector<Option> opts;
    for (uint8_t i = 0; i <= 8; ++i) {
        BadgeMode mode = (BadgeMode)i;
        opts.push_back({modeName(mode), [&m, mode]() { m.mode = mode; }});
    }
    loopOptions(opts, MENU_TYPE_SUBMENU, "Mode");
}

static void chooseBrightness(uint8_t &b) {
    std::vector<Option> opts = {
        {"100%", [&b]() { b = BADGE_BRIGHTNESS_100; }},
        {"75%",  [&b]() { b = BADGE_BRIGHTNESS_75; }},
        {"50%",  [&b]() { b = BADGE_BRIGHTNESS_50; }},
        {"25%",  [&b]() { b = BADGE_BRIGHTNESS_25; }},
    };
    loopOptions(opts, MENU_TYPE_SUBMENU, "Brightness");
}

void ledBadgeMenu() {
    static LedBadgeMessage msg;
    static uint8_t brightness = BADGE_BRIGHTNESS_100;

    while (true) {
        std::vector<Option> options;
        options.push_back(
            {"Message: " + (msg.text.length() ? msg.text : String("(empty)")),
             [&]() { msg.text = keyboard(msg.text, 40, "Badge message:"); }}
        );
        options.push_back({"Mode: " + modeName(msg.mode), [&]() { chooseMode(msg); }});
        options.push_back({"Speed: " + String(msg.speed), [&]() {
                               String s = num_keyboard(String(msg.speed), 1, "Speed 1-8:");
                               int v = s.toInt();
                               if (v < 1) v = 1;
                               if (v > 8) v = 8;
                               msg.speed = (uint8_t)v;
                           }});
        options.push_back({"Brightness: " + brightName(brightness), [&]() { chooseBrightness(brightness); }});
        options.push_back({String("Flash: ") + (msg.flash ? "On" : "Off"), [&]() { msg.flash = !msg.flash; }});
        options.push_back({String("Marquee: ") + (msg.marquee ? "On" : "Off"), [&]() { msg.marquee = !msg.marquee; }});
        options.push_back({"Send", [&]() {
                               std::vector<LedBadgeMessage> msgs = {msg};
                               std::vector<uint8_t> pkt = buildBadgePacket(msgs, brightness);
                               Serial.printf(
                                   "[LEDBadge] Send text=\"%s\" mode=%s speed=%u flash=%d marquee=%d "
                                   "bright=%s bytes=%u\n",
                                   msg.text.c_str(),
                                   modeName(msg.mode).c_str(),
                                   msg.speed,
                                   msg.flash,
                                   msg.marquee,
                                   brightName(brightness).c_str(),
                                   (unsigned)pkt.size()
                               );
                               if (sendBadgePacket(pkt)) displaySuccess("Sent!", true);
                               else displayError("Send failed", true);
                           }});
        options.push_back({"Back", [&]() {}});

        int idx = loopOptions(options, MENU_TYPE_SUBMENU, "LED Badge");
        if (check(EscPress) || idx == (int)options.size() - 1) return;
    }
}

#endif
