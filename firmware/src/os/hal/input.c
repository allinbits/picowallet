#include "os/hal/input.h"

#include "pico/stdlib.h"

#if PICOWALLET_TRUSTZONE
#include "os/secure_api.h"
#endif

#define BTN_LEFT_PIN  16
#define BTN_RIGHT_PIN 17

void input_init(void) {
    gpio_init(BTN_LEFT_PIN);
    gpio_set_dir(BTN_LEFT_PIN, GPIO_IN);
    gpio_pull_up(BTN_LEFT_PIN);

    gpio_init(BTN_RIGHT_PIN);
    gpio_set_dir(BTN_RIGHT_PIN, GPIO_IN);
    gpio_pull_up(BTN_RIGHT_PIN);
}

bool input_pressed(int btn) {
#if PICOWALLET_TRUSTZONE
    // Route through the Secure veneer so Phase 4 can clear GPIO_NSMASK
    // bits 16/17 (taking pad-config rights away from NS) without
    // breaking the read path.
    return s_input_pressed((uint8_t)btn);
#else
    int pin = (btn == INPUT_BTN_LEFT) ? BTN_LEFT_PIN : BTN_RIGHT_PIN;
    return !gpio_get(pin);
#endif
}

int input_wait_press(void) {
    // Drain any held buttons left over from a previous interaction.
    while (input_pressed(INPUT_BTN_LEFT) || input_pressed(INPUT_BTN_RIGHT)) {
        sleep_ms(5);
    }
    sleep_ms(20);

    while (1) {
        bool left  = input_pressed(INPUT_BTN_LEFT);
        bool right = input_pressed(INPUT_BTN_RIGHT);
        if (left || right) {
            sleep_ms(20); // debounce hold
            if (left  && input_pressed(INPUT_BTN_LEFT))  return INPUT_BTN_LEFT;
            if (right && input_pressed(INPUT_BTN_RIGHT)) return INPUT_BTN_RIGHT;
        }
        sleep_ms(5);
    }
}
