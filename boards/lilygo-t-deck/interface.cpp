#include "TouchDrvGT911.hpp"
#include "core/powerSave.h"
#include "core/utils.h"
#include <Wire.h>
#include <interface.h>
TouchDrvGT911 touch;

struct TouchPointPro {
    int16_t x = 0;
    int16_t y = 0;
};

// Setup for Trackball
void IRAM_ATTR ISR_up();
void IRAM_ATTR ISR_down();
void IRAM_ATTR ISR_left();
void IRAM_ATTR ISR_right();

bool trackball_interrupted = false;
// Accumulated pulse counts per direction. The trackball emits a burst of pulses per
// physical roll, so we count them and only emit a navigation step once the total on an
// axis crosses bruceConfig.trackballSensitivity (see InputHandler). Capped to avoid
// wrap-around if the ball is spun hard.
volatile int16_t trackball_up_count = 0;
volatile int16_t trackball_down_count = 0;
volatile int16_t trackball_left_count = 0;
volatile int16_t trackball_right_count = 0;
#define TRACKBALL_MAX_COUNT 1000
void IRAM_ATTR ISR_up() {
    trackball_interrupted = true;
    if (trackball_up_count < TRACKBALL_MAX_COUNT) trackball_up_count++;
}
void IRAM_ATTR ISR_down() {
    trackball_interrupted = true;
    if (trackball_down_count < TRACKBALL_MAX_COUNT) trackball_down_count++;
}
void IRAM_ATTR ISR_left() {
    trackball_interrupted = true;
    if (trackball_left_count < TRACKBALL_MAX_COUNT) trackball_left_count++;
}
void IRAM_ATTR ISR_right() {
    trackball_interrupted = true;
    if (trackball_right_count < TRACKBALL_MAX_COUNT) trackball_right_count++;
}

void ISR_rst() {
    trackball_up_count = 0;
    trackball_down_count = 0;
    trackball_left_count = 0;
    trackball_right_count = 0;
    trackball_interrupted = false;
}

#define LILYGO_KB_SLAVE_ADDRESS 0x55
#define KB_I2C_SDA 18
#define KB_I2C_SCL 8
#define SEL_BTN 0
#define UP_BTN 3
#define DW_BTN 15
#define L_BTN 2
#define R_BTN 1
#define PIN_POWER_ON 10
#define BOARD_TOUCH_INT 16
/***************************************************************************************
** Function name: _setup_gpio()
** Location: main.cpp
** Description:   initial setup for the device
***************************************************************************************/
void _setup_gpio() {
    delay(500); // time to ESP32C3 start and enable the keyboard
    if (!Wire.begin(KB_I2C_SDA, KB_I2C_SCL)) Serial.println("Fail starting ESP32-C3 keyboard");

    pinMode(PIN_POWER_ON, OUTPUT);
    digitalWrite(PIN_POWER_ON, HIGH);
    pinMode(SEL_BTN, INPUT);

    pinMode(BOARD_TOUCH_INT, INPUT);
    touch.setPins(-1, BOARD_TOUCH_INT);
    if (!touch.begin(Wire, GT911_SLAVE_ADDRESS_L)) {
        Serial.println("Failed to find GT911 - check your wiring!");
    }
    // Set touch max xy
    touch.setMaxCoordinates(320, 240);
    // Set swap xy
    touch.setSwapXY(true);
    // Set mirror xy
    touch.setMirrorXY(true, true);

    pinMode(9, OUTPUT); // LoRa Radio CS Pin to HIGH (Inhibit the SPI Communication for this module)
    digitalWrite(9, HIGH);

    // Setup for Trackball
    pinMode(UP_BTN, INPUT_PULLUP);
    attachInterrupt(UP_BTN, ISR_up, FALLING);
    pinMode(DW_BTN, INPUT_PULLUP);
    attachInterrupt(DW_BTN, ISR_down, FALLING);
    pinMode(L_BTN, INPUT_PULLUP);
    attachInterrupt(L_BTN, ISR_left, FALLING);
    pinMode(R_BTN, INPUT_PULLUP);
    attachInterrupt(R_BTN, ISR_right, FALLING);

#ifdef T_DECK_PLUS
    bruceConfigPins.gpsBaudrate = 38400;
#endif
}

/***************************************************************************************
** Function name: _post_setup_gpio()
** Location: main.cpp
** Description:   second stage gpio setup to make a few functions work
***************************************************************************************/
void _post_setup_gpio() {
#define TFT_BRIGHT_CHANNEL 0
#define TFT_BRIGHT_Bits 8
#define TFT_BRIGHT_FREQ 5000
    // Brightness control must be initialized after tft in this case @Pirata
    pinMode(TFT_BL, OUTPUT);
    ledcAttach(TFT_BL, TFT_BRIGHT_FREQ, TFT_BRIGHT_Bits);
    ledcWrite(TFT_BL, 255);
}
/*********************************************************************
** Function: setBrightness
** location: settings.cpp
** set brightness value
**********************************************************************/
void _setBrightness(uint8_t brightval) {
    int dutyCycle;
    if (brightval == 100) dutyCycle = 255;
    else if (brightval == 75) dutyCycle = 130;
    else if (brightval == 50) dutyCycle = 70;
    else if (brightval == 25) dutyCycle = 20;
    else if (brightval == 0) dutyCycle = 0;
    else dutyCycle = ((brightval * 255) / 100);

    // log_i("dutyCycle for bright 0-255: %d", dutyCycle);
    ledcWrite(TFT_BL, dutyCycle);
}
/*********************************************************************
** Function: InputHandler
** Handles the variables PrevPress, NextPress, SelPress, AnyKeyPress and EscPress
**********************************************************************/
void InputHandler(void) {
    char keyValue = 0;
    static unsigned long tm = millis();
    TouchPointPro t;
    uint8_t touched = 0;
    uint8_t rot = 5;

#ifdef NORMAL_T_DECK
    bool isPlus = false;
#else
    bool isPlus = true;
#endif
    if (rot != bruceConfigPins.rotation) {
        if (bruceConfigPins.rotation == 1) {
            touch.setMaxCoordinates(320, 240);
            touch.setSwapXY(true);
            touch.setMirrorXY(!isPlus, true);
        }
        if (bruceConfigPins.rotation == 3) {
            touch.setMaxCoordinates(320, 240);
            touch.setSwapXY(true);
            touch.setMirrorXY(isPlus, false);
        }
        if (bruceConfigPins.rotation == 0) {
            touch.setMaxCoordinates(240, 320);
            touch.setSwapXY(false);
            touch.setMirrorXY(false, !isPlus);
        }
        if (bruceConfigPins.rotation == 2) {
            touch.setMaxCoordinates(240, 320);
            touch.setSwapXY(false);
            touch.setMirrorXY(true, isPlus);
        }
        rot = bruceConfigPins.rotation;
    }
    if (bruceConfig.touchEnabled) touched = touch.getPoint(&t.x, &t.y);
    delay(1);
    Wire.requestFrom(LILYGO_KB_SLAVE_ADDRESS, 1);
    while (Wire.available() > 0) {
        keyValue = Wire.read();
        delay(1);
    }
    if (millis() - tm < 200 && !LongPress) return;

    // Trackball: up/left roll one way (Prev), down/right the other (Next). A single physical
    // roll emits several pulses; we only advance one step once the pulses on a direction reach
    // the configured sensitivity threshold, then debounce so one flick can't machine-gun.
#define TRACKBALL_DEBOUNCE_MS 90 // min gap between emitted steps
#define TRACKBALL_STALE_MS 250   // discard sub-threshold pulses after this idle time
    if (trackball_interrupted) {
        static unsigned long lastTrackballStep = 0;
        static unsigned long trackballChangedAt = 0;
        static int lastTotal = 0;

        int threshold = bruceConfig.trackballSensitivity;
        if (threshold < 1) threshold = 1;

        int prevPulses = trackball_up_count + trackball_left_count;    // up / left
        int nextPulses = trackball_down_count + trackball_right_count; // down / right
        int total = prevPulses + nextPulses;
        unsigned long now = millis();

        if (total != lastTotal) {
            trackballChangedAt = now;
            lastTotal = total;
        }

        if (prevPulses >= threshold || nextPulses >= threshold) {
            if (now - lastTrackballStep >= TRACKBALL_DEBOUNCE_MS) {
                if (!wakeUpScreen()) {
                    AnyKeyPress = true;
                    if (prevPulses >= nextPulses) PrevPress = true;
                    else NextPress = true;
                    lastTrackballStep = now;
                } else {
                    ISR_rst();
                    lastTotal = 0;
                    return;
                }
            }
            ISR_rst();
            lastTotal = 0;
        } else if (now - trackballChangedAt > TRACKBALL_STALE_MS) {
            // A nudge too small to cross the threshold; drop it so it can't accumulate later.
            ISR_rst();
            lastTotal = 0;
        }
    }

    if (keyValue != (char)0x00) {
        if (!wakeUpScreen()) {
            AnyKeyPress = true;
        } else return;
        KeyStroke.Clear();
        KeyStroke.hid_keys.push_back(keyValue);
        if (keyValue == ' ') KeyStroke.exit_key = true; // key pressed to try to exit
        if (keyValue == (char)0x08) KeyStroke.del = true;
        if (keyValue == (char)0x0D) KeyStroke.enter = true;
        if (digitalRead(SEL_BTN) == BTN_ACT) KeyStroke.fn = true;
        KeyStroke.word.push_back(keyValue);
        if (KeyStroke.del) EscPress = true;
        if (KeyStroke.enter) SelPress = true;
        KeyStroke.pressed = true;
        tm = millis();
    } else KeyStroke.pressed = false;

    if (digitalRead(SEL_BTN) == BTN_ACT) {
        tm = millis();
        if (!wakeUpScreen()) {
            AnyKeyPress = true;
        } else return;
        SelPress = true;
    }

    if ((millis() - tm) > 190 || LongPress) { // one reading each 190ms
        if (touched) {

            // Serial.printf("\nPressed x=%d , y=%d, rot: %d", t.x, t.y, bruceConfigPins.rotation);
            tm = millis();

            if (!wakeUpScreen()) AnyKeyPress = true;
            else return;

            // Touch point global variable
            touchPoint.x = t.x;
            touchPoint.y = t.y;
            touchPoint.pressed = true;
            touchHeatMap(touchPoint);
            touched = 0;
            return;
        }
    }
}

/*********************************************************************
** Function: powerOff
** location: mykeyboard.cpp
** Turns off the device (or try to)
**********************************************************************/
void powerOff() {}

/*********************************************************************
** Function: checkReboot
** location: mykeyboard.cpp
** Btn logic to turn off the device (name is odd btw)
**********************************************************************/
void checkReboot() {}
