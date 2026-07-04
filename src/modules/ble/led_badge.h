/**
 * @file led_badge.h
 * @brief Send text messages to a Bluetooth "LED name badge" (44x11, LSLED/VBLAB).
 *
 * Protocol + font ported from FOSSASIA BadgeMagic (AGPL) and led-name-badge-ls32:
 *   https://github.com/fossasia/badgemagic-app
 *   https://github.com/fossasia/led-name-badge-ls32
 *
 * The T-Deck acts as a BLE central: it scans for the badge (service 0xFEE0 / 0xFFF0),
 * connects, and writes the packet as sequential 16-byte GATT writes to 0xFEE1 / 0xFFF1.
 */
#ifndef __LED_BADGE_H__
#define __LED_BADGE_H__
#if !defined(LITE_VERSION)
#include <Arduino.h>
#include <string>
#include <vector>

// Animation modes (matches BadgeMagic Mode.kt)
enum class BadgeMode : uint8_t {
    LEFT = 0,
    RIGHT = 1,
    UP = 2,
    DOWN = 3,
    FIXED = 4,
    SNOWFLAKE = 5,
    PICTURE = 6,
    ANIMATION = 7,
    LASER = 8,
};

struct LedBadgeMessage {
    String text;
    BadgeMode mode = BadgeMode::LEFT;
    uint8_t speed = 1; // 1..8
    bool flash = false;
    bool marquee = false;
};

// Brightness header byte (led-name-badge-ls32): 0x00=100%, 0x10=75%, 0x20=50%, 0x40=25%.
static const uint8_t BADGE_BRIGHTNESS_100 = 0x00;
static const uint8_t BADGE_BRIGHTNESS_75 = 0x10;
static const uint8_t BADGE_BRIGHTNESS_50 = 0x20;
static const uint8_t BADGE_BRIGHTNESS_25 = 0x40;

// Build the full, 16-byte-aligned packet for up to 8 messages.
std::vector<uint8_t> buildBadgePacket(
    const std::vector<LedBadgeMessage> &messages, uint8_t brightness = BADGE_BRIGHTNESS_100
);

// Scan -> connect -> write -> disconnect. Returns true on success.
bool sendBadgePacket(const std::vector<uint8_t> &packet);

// On-device menu entry (registered in BleMenu.cpp).
void ledBadgeMenu();

// Headless helpers for serial commands.
bool ledBadgeSendText(const String &text); // one message, default options
void ledBadgeSelfTest();                    // encode "Hello", print hex, assert framing
void ledBadgeScanDump();                    // dump all advertising BLE devices to serial

#endif
#endif
