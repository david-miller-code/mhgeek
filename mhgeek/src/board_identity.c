#include "board_identity.h"

#include "ainice/device.h"

int mhg_board_identity_hex(char *out, size_t out_size)
{
    if (!out || out_size == 0u || out_size > 0xffffffffu) return -1;
    out[0] = '\0';
    return ainice_device_wifi_mac_hex(out, (unsigned int)out_size);
}

int mhg_board_identity_text(char *out, size_t out_size)
{
    if (!out || out_size == 0u || out_size > 0xffffffffu) return -1;
    out[0] = '\0';
    return ainice_device_wifi_mac_text(out, (unsigned int)out_size);
}
