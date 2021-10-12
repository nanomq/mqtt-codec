#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mqtt_basic.h"

int byte_number_for_variable_length(uint32_t variable)
{
    if (variable < 128) {
        return 1;
    } else if (variable < 16384) {
        return 2;
    } else if (variable < 2097152) {
        return 3;
    } else if (variable < 268435456) {
        return 4;
    }
    return 5;
}

int write_variable_length_value(uint32_t value, struct pos_buf *buf)
{
    uint8_t byte;
    int     count = 0;

    do {
        byte  = value % 128;
        value = value / 128;
        /* If there are more digits to encode, set the top bit of this digit */
        if (value > 0) {
            byte = byte | 0x80;
        }
        *(buf->curpos++) = byte;
        count++;
    } while (value > 0 && count < 5);

    if (count == 5) {
        return -1;
    }
    return count;
}

int write_byte(uint8_t val, struct pos_buf *buf)
{
    if ((buf->endpos - buf->curpos) < 1) {
        return MQTT_ERR_NOMEM;
    }

    *(buf->curpos++) = val;

    return 0;
}

int write_uint16(uint16_t value, struct pos_buf *buf)
{
    if ((buf->endpos - buf->curpos) < 2) {
        return MQTT_ERR_NOMEM;
    }

    *(buf->curpos++) = (value >> 8) & 0xFF;
    *(buf->curpos++) = value & 0xFF;

    return 0;
}

int write_byte_string(mqtt_str_t *str, struct pos_buf *buf)
{
    if ((buf->endpos - buf->curpos) < (str->length + 2)) {
        return MQTT_ERR_NOMEM;
    }
    write_uint16(str->length, buf);

    memcpy(buf->curpos, str->str, str->length);
    str->str = buf->curpos; /* reset data position to indicate data in raw data
                               block */
    buf->curpos += str->length;

    return 0;
}
