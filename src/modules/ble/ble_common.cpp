#include "ble_common.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "esp_mac.h"
#include "modules/badusb_ble/ducky_typer.h"
#if !defined(LITE_VERSION)
#include "BLE_Suite.h"
#endif
#define SERVICE_UUID "1bc68b2a-f3e3-11e9-81b4-2a2ae2dbcce4"
#define CHARACTERISTIC_RX_UUID "1bc68da0-f3e3-11e9-81b4-2a2ae2dbcce4"
#define CHARACTERISTIC_TX_UUID "1bc68efe-f3e3-11e9-81b4-2a2ae2dbcce4"

BLEScan *pBLEScan = nullptr;
int scanTime = SCANTIME; // In seconds

#if __has_include(<NimBLEExtAdvertising.h>)
#define NIMBLE_V2_PLUS 1
#endif

#define ENDIAN_CHANGE_U16(x) ((((x) & 0xFF00) >> 8) + (((x) & 0xFF) << 8))

BLEServer *pServer = NULL;
BLEService *pService = NULL;
BLECharacteristic *pTxCharacteristic;
BLECharacteristic *pRxCharacteristic;
bool bleDataTransferEnabled = false;

bool deviceConnected = false;
bool oldDeviceConnected = false;

class MyServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer *pServer) { deviceConnected = true; };

    void onDisconnect(BLEServer *pServer) { deviceConnected = false; }
};

class MyCallbacks : public BLECharacteristicCallbacks {
    NimBLEAttValue data;
    void onWrite(NimBLECharacteristic *pCharacteristic) { data = pCharacteristic->getValue(); }
};

uint8_t sta_mac[6];
char strID[18];
char strAddl[200];

// Resolve a Bluetooth SIG company identifier (the first 2 bytes of manufacturer-
// specific advertising data) to a vendor name. Covers the common consumer vendors;
// unknown IDs return "". Works even for devices using randomized/private addresses,
// since the company ID is in the advertised payload, not the MAC.
static String bleCompanyName(uint16_t id) {
    switch (id) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x00E0: return "Google";
    case 0x0075: return "Samsung";
    case 0x0087: return "Garmin";
    case 0x009E: return "Bose";
    case 0x012D: return "Sony";
    case 0x0157: return "Huami/Amazfit";
    case 0x038F: return "Xiaomi";
    case 0x0059: return "Nordic Semi";
    case 0x0171: return "Amazon";
    case 0x02E5: return "Espressif";
    case 0x000D: return "Texas Instruments";
    case 0x000F: return "Broadcom";
    case 0x0002: return "Intel";
    case 0x000A: return "Qualcomm/CSR";
    case 0x00C4: return "LG Electronics";
    case 0x0001: return "Nokia";
    case 0x0004: return "Toshiba";
    case 0x0499: return "Ruuvi";
    case 0x0078: return "Nike";
    default: return "";
    }
}

// Map a GAP Appearance value to a human category label ("" if unknown/absent).
static String bleAppearanceName(uint16_t a) {
    if (a == 0) return "";
    switch (a >> 6) { // top 10 bits = category
    case 1: return "Phone";
    case 2: return "Computer";
    case 3: return "Watch";
    case 4: return "Clock";
    case 5: return "Display";
    case 6: return "Remote";
    case 7: return "Glasses";
    case 8: return "Tag";
    case 9: return "Keyring";
    case 10: return "Media Player";
    case 11: return "Barcode Scanner";
    case 12: return "Thermometer";
    case 13: return "Heart Rate";
    case 14: return "Blood Pressure";
    case 15:
        switch (a) {
        case 0x03C1: return "Keyboard";
        case 0x03C2: return "Mouse";
        case 0x03C3: return "Joystick";
        case 0x03C4: return "Gamepad";
        default: return "HID";
        }
    case 16: return "Glucose Meter";
    case 17: return "Run/Walk Sensor";
    case 18: return "Cycling";
    case 20: return "Pulse Oximeter";
    case 21: return "Weight Scale";
    case 49: return "Outdoor Sports";
    default: return "";
    }
}

// Walk the raw advertising payload's AD structures to pull the manufacturer
// company ID (type 0xFF) and the Appearance (type 0x19), for name resolution.
static void bleParsePayload(const NimBLEAdvertisedDevice *d, uint16_t &companyId, uint16_t &appearance) {
    companyId = 0;
    appearance = 0;
    const std::vector<uint8_t> &pl = d->getPayload();
    size_t plen = pl.size();
    size_t i = 0;
    while (i + 1 < plen) {
        uint8_t len = pl[i];
        if (len == 0 || i + 1 + len > plen) break;
        uint8_t type = pl[i + 1];
        if (type == 0xFF && len >= 3) companyId = pl[i + 2] | (pl[i + 3] << 8);
        else if (type == 0x19 && len >= 3) appearance = pl[i + 2] | (pl[i + 3] << 8);
        i += 1 + len;
    }
}

void ble_info(
    String name, String address, String signal, String vendor = "", String appearance = ""
) {
    drawMainBorder();
    tft.setTextColor(bruceConfig.priColor);
    tft.drawCentreString("-=Information=-", tftWidth / 2, 28, SMOOTH_FONT);
    tft.drawString("Name: " + name, 10, 48);
    tft.drawString("Adresse: " + address, 10, 66);
    tft.drawString("Signal: " + String(signal) + " dBm", 10, 84);
    int y = 102;
    if (!vendor.isEmpty()) {
        tft.drawString("Vendor: " + vendor, 10, y);
        y += 18;
    }
    if (!appearance.isEmpty()) { tft.drawString("Type: " + appearance, 10, y); }
    tft.drawCentreString("Backspace: back to list", tftWidth / 2, tftHeight - 20, 1);

    delay(300);
    check(EscPress); // clear any stale press from entering this screen
    check(SelPress);
    while (true) {
        if (check(EscPress)) return; // Backspace -> back to the scan list
        check(SelPress);             // Mid is a no-op here; swallow it so it doesn't leak to the list
        yield();
    }
}
// Build one scan-list entry with name resolution: use the advertised name when
// present; otherwise fall back to the resolved vendor "[Apple]" (from the company
// ID), and only then the bare address. The detail view gets vendor + device type.
static void addBleScanOption(const NimBLEAdvertisedDevice *d) {
    if (options.size() >= 250) {
        Serial.println("Memory low, stopping BLE scan...");
        if (pBLEScan) pBLEScan->stop();
        return;
    }
    String name = d->getName().c_str();
    String address = d->getAddress().toString().c_str();
    String signal = String(d->getRSSI());

    uint16_t companyId = 0, appr = 0;
    bleParsePayload(d, companyId, appr);
    String vendor = companyId ? bleCompanyName(companyId) : "";
    String appearance = bleAppearanceName(appr);

    String title;
    if (!name.isEmpty()) title = name;
    else if (!vendor.isEmpty()) title = "[" + vendor + "]";
    else title = address;
    String infoName = name.isEmpty() ? "<no name>" : name;

    options.emplace_back(title.c_str(), [=]() { ble_info(infoName, address, signal, vendor, appearance); });
}

#ifdef NIMBLE_V2_PLUS
class AdvertisedDeviceCallbacks : public NimBLEScanCallbacks {
#else
class AdvertisedDeviceCallbacks : public NimBLEAdvertisedDeviceCallbacks {
#endif
    void onResult(NimBLEAdvertisedDevice *advertisedDevice) { addBleScanOption(advertisedDevice); }
};

static bool is_ble_inited = false;

void stopBLEStack() {
    if (pBLEScan) pBLEScan->stop();

#if !defined(LITE_VERSION)
    if (BLEStateManager::isBLEActive() || BLEStateManager::getActiveClientCount() > 0) {
        BLEStateManager::deinitBLE(true);
    } else
#endif
        if (BLEDevice::getScan() != nullptr || BLEDevice::getAdvertising() != nullptr ||
            BLEDevice::getServer() != nullptr || BLEConnected || is_ble_inited) {
        BLEDevice::deinit();
    }

    pBLEScan = nullptr;
    pServer = nullptr;
    pService = nullptr;
    pTxCharacteristic = nullptr;
    pRxCharacteristic = nullptr;
    deviceConnected = false;
    oldDeviceConnected = false;
    bleDataTransferEnabled = false;
    is_ble_inited = false;
    BLEConnected = false;
#if !defined(LITE_VERSION)
    if (hid_ble) {
        delete hid_ble;
        hid_ble = nullptr;
    }
#endif
}

void ble_scan_setup() {
    if (FORCE_RADIO_TEARDOWN_ON_SWITCH) {
        if (WiFi.getMode() != WIFI_MODE_NULL || wifiConnected) {
            wifiDisconnect();
            delay(200);
        }

        stopBLEStack();
        delay(100);
    }

    BLEDevice::init("");
    pBLEScan = BLEDevice::getScan();
#ifdef NIMBLE_V2_PLUS
    pBLEScan->setScanCallbacks(new NimBLEScanCallbacks());
#else
    pBLEScan->setAdvertisedDeviceCallbacks(new AdvertisedDeviceCallbacks());
#endif

    // Active scan uses more power, but get results faster
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(SCAN_INT);
    // Less or equal setInterval value
    pBLEScan->setWindow(SCAN_WINDOW);

    // Bluetooth MAC Address
#ifdef NIMBLE_V2_PLUS
    esp_read_mac(sta_mac, ESP_MAC_BT);
#else
    esp_read_mac(sta_mac, ESP_MAC_BT);
#endif

    sprintf(
        strID,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        sta_mac[0],
        sta_mac[1],
        sta_mac[2],
        sta_mac[3],
        sta_mac[4],
        sta_mac[5]
    );
    vTaskDelay(100 / portTICK_PERIOD_MS);
}

void ble_scan() {
    displayTextLine("Scanning..");

    options = {};
    ble_scan_setup();
#ifdef NIMBLE_V2_PLUS
    BLEScanResults foundDevices = pBLEScan->getResults(scanTime * 1000, false);
    for (int i = 0; i < foundDevices.getCount(); i++) {
        addBleScanOption(foundDevices.getDevice(i));
    }
#else
    BLEScanResults foundDevices = pBLEScan->start(scanTime, false);
#endif

    addOptionToMainMenu();

    // loopOptions() exits the list every time a selected item's callback returns,
    // so re-show it in a loop: viewing a device (ble_info) returns here with
    // returnToMenu still false (Backspace = back to list); it's only left when
    // ble_info's "act" sets returnToMenu, the "Main Menu" item is chosen, or
    // Backspace is pressed on the list itself (loopOptions returns -1).
    while (!returnToMenu) {
        if (loopOptions(options) == -1) break;
    }
    options.clear();

    // Delete results fromBLEScan buffer to release memory
    pBLEScan->clearResults();
}

bool initBLEServer() {
    uint64_t chipid = ESP.getEfuseMac();
    String blename = "Bruce-" + String((uint8_t)(chipid >> 32), HEX);

    BLEDevice::init(blename.c_str());
    // BLEDevice::setPower(ESP_PWR_LVL_N12);
    pServer = BLEDevice::createServer();

    pServer->setCallbacks(new MyServerCallbacks());
    pService = pServer->createService(SERVICE_UUID);
    pTxCharacteristic = pService->createCharacteristic(CHARACTERISTIC_RX_UUID, NIMBLE_PROPERTY::NOTIFY);

    pTxCharacteristic->addDescriptor(new NimBLE2904());
    BLECharacteristic *pRxCharacteristic = pService->createCharacteristic(
        CHARACTERISTIC_TX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    pRxCharacteristic->setCallbacks(new MyCallbacks());

    return true;
}

void disPlayBLESend() {
    uint8_t senddata[2] = {0};
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(); // Moved up to avoid drawing screen issues
    tft.setTextSize(1);

    pService->start();
    pServer->getAdvertising()->start();

    uint64_t chipid = ESP.getEfuseMac();
    String blename = "Bruce-" + String((uint8_t)(chipid >> 32), HEX);

    BLEConnected = true;

    bool wasConnected = false;
    bool first_run = true;
    while (!check(EscPress)) {
        if (deviceConnected) {
            if (!wasConnected) {
                tft.fillRect(10, 26, tftWidth - 20, tftHeight - 36, TFT_BLACK);
                drawBLE_beacon(180, 28, TFT_BLUE);
                tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
                tft.setTextSize(FM);
                tft.setCursor(12, 50);
                // tft.printf("BLE connect!\n");
                tft.printf("BLE Send\n");
                tft.setTextSize(FM);
            }
            tft.fillRect(10, 100, tftWidth - 20, 28, TFT_BLACK);
            tft.setCursor(12, 100);
            if (senddata[0] % 4 == 0) {
                tft.printf("0x%02X>    ", senddata[0]);
            } else if (senddata[0] % 4 == 1) {
                tft.printf("0x%02X>>   ", senddata[0]);
            } else if (senddata[0] % 4 == 2) {
                tft.printf("0x%02X >>  ", senddata[0]);
            } else if (senddata[0] % 4 == 3) {
                tft.printf("0x%02X  >  ", senddata[0]);
            }

            senddata[1]++;
            if (senddata[1] > 3) {
                senddata[1] = 0;
                senddata[0]++;
                pTxCharacteristic->setValue(senddata, 1);
                pTxCharacteristic->notify();
            }
            wasConnected = true;
        } else {
            if (wasConnected or first_run) {
                first_run = false;
                tft.fillRect(10, 26, tftWidth - 20, tftHeight - 36, TFT_BLACK);
                tft.setTextSize(FM);
                tft.setCursor(12, 50);
                tft.setTextColor(TFT_RED);
                tft.printf("BLE disconnect\n");
                tft.setCursor(12, 75);
                tft.setTextColor(tft.color565(18, 150, 219));

                tft.printf(String("Name:" + blename + "\n").c_str());
                tft.setCursor(12, 100);
                tft.printf("UUID:1bc68b2a\n");
                drawBLE_beacon(180, 40, TFT_DARKGREY);
            }
            wasConnected = false;
        }
    }

    tft.setTextColor(TFT_WHITE);
    pService->~NimBLEService();
    pServer->getAdvertising()->stop();
#if defined(CONFIG_IDF_TARGET_ESP32C5)
    esp_bt_controller_deinit();
#else
    BLEDevice::deinit();
#endif
    BLEConnected = false;
}

void ble_test() {
    printf("ble test\n");

    // if (!is_ble_inited)
    // {
    printf("Init ble server\n");
    initBLEServer();
    delay(100);
    is_ble_inited = true;
    // }

    disPlayBLESend();

    printf("Quit ble test\n");
}
