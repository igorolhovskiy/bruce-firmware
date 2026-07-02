
// #ifndef __LORA_MENU_H__
// #define __LORA_MENU_H__
#ifndef __LORA_RF_H__
#define __LORA_RF_H__
#if !defined(LITE_VERSION)
#include "HWCDC.h"
#include <SPI.h>
void lorachat();
void loraconf();

// Pin / SPI-bus helpers, also reused by LoRaRecon for its own independent
// radio bring-up (handles the T-Deck's shared TFT/SD/CC1101 SPI bus cases).
int getLoraIrqPin();
int getLoraBusyPin();
int getLoraResetPin();
int getLoraCsPin();
SPIClass *selectLoraSPIBus();
#endif
#endif
