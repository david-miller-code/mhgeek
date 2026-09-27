#ifndef MHGEEK_BOARD_IDENTITY_H
#define MHGEEK_BOARD_IDENTITY_H

#include <stddef.h>

/* The board identity the product already uses: the locally administered Wi-Fi
 * MAC of this device, exactly as the HomeAssistant plugin derives its device
 * identity (`ainice-vision-<mac>`). The shared SDK helper validates the
 * locally-administered bit, so a randomized or missing address fails instead of
 * silently producing a different identity on every boot. */
int mhg_board_identity_hex(char *out, size_t out_size);

/* The same address in the `aa:bb:cc:dd:ee:ff` form, for display names. */
int mhg_board_identity_text(char *out, size_t out_size);

#endif
