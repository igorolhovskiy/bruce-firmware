#include "cs_gps.h"

#include <HardwareSerial.h>
#include <TinyGPS++.h>
#include <globals.h>
#include <math.h>
#include <string.h>

namespace csgps {

namespace {

HardwareSerial gpsSerial(2);
TinyGPSPlus gps;
Mode curMode = MODE_ON;
bool running = false;
bool dataSeen = false;
bool isUblox = false; // answered UBX-MON-VER
bool isM10 = false;   // ...and identified as an M10 (config keys below known)
char tag[16] = "GPS";
bool hadFix = false;

// Last GOOD position, captured when TinyGPS commits a new location (only done
// from a sentence that has a fix), with the satellite count of that moment.
bool goodValid = false;
float goodLat = 0, goodLon = 0;
uint8_t goodSats = 0;
uint32_t goodMs = 0;

// ── Minimal UBX framing (only ACK / NAK / MON-VER are consumed) ──────────────
uint8_t ubxState = 0, ubxCls = 0, ubxId = 0;
uint16_t ubxLen = 0, ubxPos = 0;
uint8_t ubxBuf[200];
uint8_t ubxCkA = 0, ubxCkB = 0;
// Last ACK/NAK seen for a CFG-VALSET: 0 = none, 1 = ACK, 2 = NAK.
volatile uint8_t valsetResult = 0;
bool monVerSeen = false;

void onUbx() {
    if (ubxCls == 0x05 && ubxLen >= 2 && ubxBuf[0] == 0x06 && ubxBuf[1] == 0x8A)
        valsetResult = ubxId == 0x01 ? 1 : 2;
    if (ubxCls == 0x0A && ubxId == 0x04 && ubxLen >= 40) {
        monVerSeen = true;
        isUblox = true;
        char sw[31], hw[11];
        memcpy(sw, ubxBuf, 30);
        sw[30] = 0;
        memcpy(hw, ubxBuf + 30, 10);
        hw[10] = 0;
        // M10 hardware version is 000A0000; extensions also carry e.g. "MOD=MIA-M10Q".
        isM10 = strncmp(hw, "000A0000", 8) == 0;
        Serial.printf("[%s] GPS module: u-blox sw=\"%s\" hw=%s\n", tag, sw, hw);
        for (uint16_t off = 40; off + 30 <= ubxLen && off + 30 <= sizeof(ubxBuf); off += 30) {
            char ext[31];
            memcpy(ext, ubxBuf + off, 30);
            ext[30] = 0;
            if (strstr(ext, "M10")) isM10 = true;
            if (!strncmp(ext, "MOD=", 4)) Serial.printf("[%s] GPS %s\n", tag, ext);
        }
    }
}

void feed(uint8_t b) {
    switch (ubxState) {
    case 0:
        if (b == 0xB5) ubxState = 1;
        else gps.encode((char)b);
        return;
    case 1:
        if (b == 0x62) {
            ubxState = 2;
            ubxCkA = ubxCkB = 0;
        } else {
            ubxState = 0;
            gps.encode((char)b);
        }
        return;
    }
    if (ubxState < 7) { // header bytes count toward the checksum
        ubxCkA += b;
        ubxCkB += ubxCkA;
    }
    switch (ubxState) {
    case 2: ubxCls = b; ubxState = 3; break;
    case 3: ubxId = b; ubxState = 4; break;
    case 4: ubxLen = b; ubxState = 5; break;
    case 5:
        ubxLen |= (uint16_t)b << 8;
        ubxPos = 0;
        ubxState = ubxLen ? 6 : 7;
        break;
    case 6:
        if (ubxPos < sizeof(ubxBuf)) ubxBuf[ubxPos] = b;
        if (++ubxPos >= ubxLen) ubxState = 7;
        break;
    case 7: ubxState = b == ubxCkA ? 8 : 0; break;
    case 8:
        if (b == ubxCkB) onUbx();
        ubxState = 0;
        break;
    default: ubxState = 0;
    }
}

void ubxSend(uint8_t cls, uint8_t id, const uint8_t *pl, uint16_t len) {
    uint8_t hdr[6] = {0xB5, 0x62, cls, id, (uint8_t)(len & 0xFF), (uint8_t)(len >> 8)};
    uint8_t a = 0, b = 0;
    for (int i = 2; i < 6; i++) {
        a += hdr[i];
        b += a;
    }
    for (uint16_t i = 0; i < len; i++) {
        a += pl[i];
        b += a;
    }
    gpsSerial.write(hdr, 6);
    if (len) gpsSerial.write(pl, len);
    gpsSerial.write(a);
    gpsSerial.write(b);
}

// Pump the UART for up to `ms`, returning early once `done()` holds.
template <typename F> void pumpFor(uint32_t ms, F done) {
    uint32_t t0 = millis();
    while (millis() - t0 < ms) {
        while (gpsSerial.available() > 0) {
            dataSeen = true;
            feed((uint8_t)gpsSerial.read());
        }
        if (done()) return;
        delay(5);
    }
}

// One CFG-VALSET (RAM layer only: a power cycle restores defaults). Keys whose
// size nibble is 1 (bit) or 2 take 1 byte, 3 takes 2, 4 takes 4. The receiver
// may be asleep in power-save mode, so wake it with a few 0xFF bytes first and
// retry. Returns true on ACK.
struct KV {
    uint32_t key;
    uint32_t val;
};
bool valset(const KV *kv, int n, const char *what) {
    uint8_t pl[4 + 8 * 8];
    int len = 4;
    pl[0] = 0; // version
    pl[1] = 0x01; // RAM
    pl[2] = pl[3] = 0;
    for (int i = 0; i < n && len + 8 <= (int)sizeof(pl); i++) {
        for (int k = 0; k < 4; k++) pl[len++] = (kv[i].key >> (8 * k)) & 0xFF;
        uint8_t sz = (kv[i].key >> 28) & 0x07;
        int bytes = sz <= 2 ? 1 : sz == 3 ? 2 : 4;
        for (int k = 0; k < bytes; k++) pl[len++] = (kv[i].val >> (8 * k)) & 0xFF;
    }
    for (int attempt = 0; attempt < 3; attempt++) {
        for (int k = 0; k < 8; k++) gpsSerial.write((uint8_t)0xFF);
        delay(attempt ? 150 : 20);
        valsetResult = 0;
        ubxSend(0x06, 0x8A, pl, len);
        pumpFor(400, [] { return valsetResult != 0; });
        if (valsetResult == 2) Serial.printf("[%s] GPS cfg %s: NAK\n", tag, what);
        if (valsetResult) return valsetResult == 1;
    }
    Serial.printf("[%s] GPS cfg %s: no reply\n", tag, what);
    return false;
}

// M10 configuration keys (u-blox M10 SPG 5.10 interface description).
constexpr uint32_t K_PM_OPERATEMODE = 0x20D00001; // 0 full power, 1 PSMOO, 2 PSMCT
constexpr uint32_t K_NMEA_GGA = 0x209100BB, K_NMEA_RMC = 0x209100AC, K_NMEA_GSV = 0x209100C5,
                   K_NMEA_GSA = 0x209100C0, K_NMEA_GLL = 0x209100CA, K_NMEA_VTG = 0x209100B1;

// Power-save is deliberately NOT used. Measured on-device (MIA-M10Q by a
// window): power-save ON/OFF mode never produced a fix, and the receiver lost
// its satellite data while asleep - afterwards even full power needed 100 s to
// >12 min to get a position again. Continuous tracking costs roughly 8-10 mA,
// a few percent of a WiFi/BLE scan + backlight, so the GPS stays at full power
// and only the unused NMEA output is trimmed.
void applyMode() {
    if (!isUblox) return;
    // Only RMC (position) + GGA (sats/HDOP) are parsed; drop the rest while on.
    bool trim = curMode == MODE_ON;
    const KV nmea[] = {{K_NMEA_GSV, trim ? 0u : 1u}, {K_NMEA_GSA, trim ? 0u : 1u},
                       {K_NMEA_GLL, trim ? 0u : 1u}, {K_NMEA_VTG, trim ? 0u : 1u},
                       {K_NMEA_GGA, 1}, {K_NMEA_RMC, 1}};
    valset(nmea, 6, trim ? "nmea trim" : "nmea restore");
    if (isM10) { // undo any power-save mode left over from elsewhere
        const KV pm[] = {{K_PM_OPERATEMODE, 0}};
        valset(pm, 1, "full power");
    }
}

constexpr uint32_t MAX_FIX_AGE_MS = 5000;
} // namespace

Mode mode() { return curMode; }
const char *modeName() { return curMode == MODE_OFF ? "off" : "on"; }

void begin(const char *t) {
    strlcpy(tag, t, sizeof(tag));
    if (curMode == MODE_OFF || running) return;
    pinMode(bruceConfigPins.gps_bus.rx, INPUT);
    gpsSerial.setRxBufferSize(1024);
    gpsSerial.begin(bruceConfigPins.gpsBaudrate, SERIAL_8N1, bruceConfigPins.gps_bus.rx,
                    bruceConfigPins.gps_bus.tx);
    running = true;
    hadFix = false;
    goodValid = false;
    ubxState = 0;
    pumpFor(1500, [] { return dataSeen; });
    if (!dataSeen) {
        Serial.printf("[%s] GPS: no data on UART (no module / wrong pins?) - will keep listening\n", tag);
        return;
    }
    if (!monVerSeen) {
        ubxSend(0x0A, 0x04, nullptr, 0); // UBX-MON-VER poll
        pumpFor(1000, [] { return monVerSeen; });
        if (!monVerSeen) Serial.printf("[%s] GPS: NMEA-only module (no UBX reply)\n", tag);
    }
    applyMode();
    Serial.printf("[%s] GPS on\n", tag);
}

void end() {
    if (!running) return;
    if (isUblox) { // leave the receiver as other Bruce GPS apps expect it
        Mode keep = curMode;
        curMode = MODE_OFF;
        applyMode(); // NMEA back to defaults + (M10) full power
        curMode = keep;
    }
    gpsSerial.end();
    running = false;
}

void cycleMode() {
    if (curMode == MODE_ON) {
        end();
        curMode = MODE_OFF;
    } else {
        curMode = MODE_ON;
        begin(tag);
    }
    Serial.printf("[%s] GPS mode -> %s\n", tag, modeName());
}

void poll() {
    if (!running) return;
    int n = 0;
    while (gpsSerial.available() > 0 && n++ < 512) {
        dataSeen = true;
        feed((uint8_t)gpsSerial.read());
    }
    if (gps.location.isUpdated()) { // committed only from a sentence that HAS a fix
        double lat = gps.location.lat(), lon = gps.location.lng(); // reading clears isUpdated
        uint8_t sats = gps.satellites.isValid() ? (uint8_t)gps.satellites.value() : 0;
        float hdop = gps.hdop.isValid() ? gps.hdop.hdop() : 99.0f; // > 5: too imprecise
        if (sats >= 4 && hdop <= 5.0f) {
            goodValid = true;
            goodLat = (float)lat;
            goodLon = (float)lon;
            goodSats = sats;
            goodMs = millis();
        }
    }
    Fix f;
    bool ok = fix(f);
    if (ok && !hadFix) {
        Serial.printf("[%s] GPS fix acquired (%u sats)\n", tag, f.sats);
    } else if (!ok && hadFix) {
        Serial.printf("[%s] GPS fix lost\n", tag);
    }
    hadFix = ok;
}

bool fix(Fix &out) {
    if (!running || !goodValid || millis() - goodMs > MAX_FIX_AGE_MS) return false;
    out.lat = goodLat;
    out.lon = goodLon;
    out.sats = goodSats;
    return true;
}

const char *statusStr() {
    static char buf[24];
    Fix f;
    if (curMode == MODE_OFF) return "gps:off";
    if (!dataSeen) return "gps:none";
    if (!fix(f)) return "gps:wait";
    snprintf(buf, sizeof(buf), "gps:%usat", f.sats);
    return buf;
}

// Equirectangular approximation: well under 1% error at these (km) scales.
float distM(float lat1, float lon1, float lat2, float lon2) {
    constexpr float R = 6371000.0f, D2R = 0.0174532925f;
    float x = (lon2 - lon1) * D2R * cosf((lat1 + lat2) * 0.5f * D2R);
    float y = (lat2 - lat1) * D2R;
    return R * sqrtf(x * x + y * y);
}

void trackUpdate(Track &t, const Fix &f) {
    if (!t.has) {
        t.lat0 = t.anchLat = f.lat;
        t.lon0 = t.anchLon = f.lon;
        t.maxDistM = 0;
        t.places = 1;
        t.has = 1;
        return;
    }
    float d0 = distM(t.lat0, t.lon0, f.lat, f.lon);
    if (d0 > t.maxDistM) t.maxDistM = d0 > 65535.0f ? 65535 : (uint16_t)d0;
    if (distM(t.anchLat, t.anchLon, f.lat, f.lon) >= PLACE_STEP_M) {
        t.anchLat = f.lat;
        t.anchLon = f.lon;
        if (t.places < 255) t.places++;
    }
}

bool selfTest() {
    bool ok = true;
    float d = distM(50.0f, 30.0f, 50.001f, 30.0f); // ~111 m north
    ok &= d > 105 && d < 118;
    Track t = {};
    trackUpdate(t, {50.0f, 30.0f, 8});
    trackUpdate(t, {50.0015f, 30.0f, 8}); // ~167 m: place 2
    bool early = movedWithYou(t);
    trackUpdate(t, {50.0040f, 30.0f, 8}); // ~445 m: place 3
    ok &= !early && movedWithYou(t);
    Track j = {}; // GPS jitter around one spot must never count as movement
    for (int i = 0; i < 20; i++) trackUpdate(j, {50.0f + (i % 3) * 0.0002f, 30.0f + (i % 2) * 0.0002f, 8});
    ok &= !movedWithYou(j) && j.places == 1;
    Serial.printf("[%s] cs_gps self-test %s (d=%.0f m, places=%u max=%u m, jitter places=%u)\n", tag,
                  ok ? "PASS" : "FAIL", d, t.places, t.maxDistM, j.places);
    return ok;
}

} // namespace csgps
