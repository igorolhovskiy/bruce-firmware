// T-Deck microphone codec hook.
//
// The T-Deck's microphones are fronted by an ES7210 4-channel ADC that must be
// configured over I2C (the shared keyboard bus, Wire) before the ESP32 I2S RX
// channel can read any audio. modules/others/mic.cpp declares _setup_codec_mic()
// as a weak no-op; this strong definition (compiled only for the T-Deck, and only
// when MIC_ES7210 is enabled) brings the codec up/down around each capture.
//
// I2S wiring (set in lilygo-t-deck.ini): MCLK=48, SCK/BCLK=47, WS/LRCK=21, DIN=14.
// Note: driving MCLK on GPIO48 means the NeoPixel/trackball-centre (GPIO0) are
// unavailable while the mic is active — a known T-Deck hardware limitation.

#if defined(MIC_ES7210)

#include "es7210.h"
#include <Wire.h>

void _setup_codec_mic(bool enable) {
    if (enable) {
        audio_hal_codec_config_t cfg = {};
        cfg.adc_input = AUDIO_HAL_ADC_INPUT_ALL;
        cfg.dac_output = AUDIO_HAL_DAC_OUTPUT_ALL;
        cfg.codec_mode = AUDIO_HAL_CODEC_MODE_ENCODE; // ADC only
        cfg.i2s_iface.mode = AUDIO_HAL_MODE_SLAVE;    // ESP32 is the I2S master
        cfg.i2s_iface.fmt = AUDIO_HAL_I2S_NORMAL;
        cfg.i2s_iface.samples = AUDIO_HAL_48K_SAMPLES; // matches MIC_SAMPLE_RATE
        cfg.i2s_iface.bits = AUDIO_HAL_BIT_LENGTH_16BITS;

        es7210_adc_init(&Wire, &cfg);
        es7210_adc_config_i2s(cfg.codec_mode, &cfg.i2s_iface);
        es7210_adc_set_gain(
            (es7210_input_mics_t)(ES7210_INPUT_MIC1 | ES7210_INPUT_MIC2), GAIN_30DB
        );
        es7210_adc_set_gain(
            (es7210_input_mics_t)(ES7210_INPUT_MIC3 | ES7210_INPUT_MIC4), GAIN_37_5DB
        );
        es7210_adc_ctrl_state(cfg.codec_mode, AUDIO_HAL_CTRL_START);
    } else {
        es7210_adc_ctrl_state(AUDIO_HAL_CODEC_MODE_ENCODE, AUDIO_HAL_CTRL_STOP);
        es7210_adc_deinit();
    }
}

#endif // MIC_ES7210
