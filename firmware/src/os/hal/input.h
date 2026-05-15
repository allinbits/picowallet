#pragma once
#include <stdbool.h>

#define INPUT_BTN_LEFT  0
#define INPUT_BTN_RIGHT 1

void input_init(void);
bool input_pressed(int btn);

// Blocks until a button is pressed (with debounce). Returns INPUT_BTN_LEFT or
// INPUT_BTN_RIGHT. Waits for any held buttons to be released first so callers
// don't see a stale press from the previous interaction.
int  input_wait_press(void);
