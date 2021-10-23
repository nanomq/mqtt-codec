#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/mqtt_basic.h"

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

int write_byte_string(mqtt_buf_t *str, struct pos_buf *buf)
{
    if ((buf->endpos - buf->curpos) < (str->length + 2)) {
        return MQTT_ERR_NOMEM;
    }
    write_uint16(str->length, buf);

    memcpy(buf->curpos, str->buf, str->length);
    str->buf = buf->curpos; /* reset data position to indicate data in raw data
                               block */
    buf->curpos += str->length;

    return 0;
}

int read_byte(struct pos_buf *buf, uint8_t *val)
{
    if ((buf->endpos - buf->curpos) < 1) {
        return MQTT_ERR_NOMEM;
    }

    *val = *(buf->curpos++);

    return 0;
}

int read_uint16(struct pos_buf *buf, uint16_t *val)
{
    if ((size_t)(buf->endpos - buf->curpos) < sizeof(uint16_t)) {
        return MQTT_ERR_INVAL;
    }

    *val = *(buf->curpos++) << 8; /* MSB */
    *val |= *(buf->curpos++);     /* LSB */

    return 0;
}

int read_utf8_str(struct pos_buf *buf, mqtt_buf_t *val)
{
    uint16_t length = 0;
    int      ret    = read_uint16(buf, &length);
    if (ret != 0) {
        return ret;
    }
    if ((buf->endpos - buf->curpos) < length) {
        return MQTT_ERR_INVAL;
    }

    val->length = length;
    /* Zero length UTF8 strings are permitted. */
    if (length > 0) {
        val->buf = buf->curpos;
        buf->curpos += length;
    } else {
        val->buf = NULL;
    }
    return 0;
}

int read_str_data(struct pos_buf *buf, mqtt_buf_t *val)
{
    uint16_t length = 0;
    int      ret    = read_uint16(buf, &length);
    if (ret != 0) {
        return ret;
    }
    if ((buf->endpos - buf->curpos) < length) {
        return MQTT_ERR_INVAL;
    }

    val->length = length;
    if (length > 0) {
        val->buf = buf->curpos;
        buf->curpos += length;
    } else {
        val->buf = NULL;
    }
    return 0;
}

int read_packet_length(struct pos_buf *buf, uint32_t *length)
{
    uint8_t  shift = 0;
    uint32_t bytes = 0;

    *length = 0;
    do {
        if (bytes >= MQTT_MAX_MSG_LEN) {
            return MQTT_ERR_INVAL;
        }

        if (buf->curpos >= buf->endpos) {
            return MQTT_ERR_MALFORMED;
        }

        *length += ((uint32_t) * (buf->curpos) & MQTT_LENGTH_VALUE_MASK)
            << shift;
        shift += MQTT_LENGTH_SHIFT;
        bytes++;
    } while ((*(buf->curpos++) & MQTT_LENGTH_CONTINUATION_BIT) != 0U);

    if (*length > MQTT_MAX_MSG_LEN) {
        return MQTT_ERR_INVAL;
    }

    return 0;
}

mqtt_buf_t mqtt_buf_dup(const mqtt_buf_t *src)
{
    mqtt_buf_t dest;

    dest.length = src->length;
    dest.buf    = malloc(dest.length);
    memcpy(dest.buf, src->buf, dest.length);
    return dest;
}

void mqtt_buf_free(mqtt_buf_t *buf)
{
    free(buf->buf);
}
