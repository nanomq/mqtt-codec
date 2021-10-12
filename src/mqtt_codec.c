
#include "mqtt_codec.h"
#include "mqtt_basic.h"
#include "mqtt_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

mqtt_msg *mqtt_msg_create_empty(void)
{
    mqtt_msg *msg = (mqtt_msg *) malloc(sizeof(mqtt_msg));
    memset((char *) msg, 0, sizeof(mqtt_msg));

    return msg;
}

int mqtt_msg_destroy(mqtt_msg *self)
{
    if (self->entire_raw_msg.str) {
        /* If we are builder or a is_parser that have an attached raw data,
         * we should destroy raw data too. */
        if ((!self->is_parser) || (self->is_parser && self->attached_raw)) {
            free(self->entire_raw_msg.str);
        }
        self->entire_raw_msg.str    = NULL;
        self->entire_raw_msg.length = 0;
    }
    free(self);

    return 0;
}

uint8_t encode_connect_flags(conn_flags *flags_set)
{
    uint8_t connflags = 0;

    if (flags_set->clean_session) {
        connflags |= CONN_FLAG_CLEAN_SESSION;
    }
    if (flags_set->will_flag) {
        connflags |= CONN_FLAG_WILL_FLAG;
    }
    if (flags_set->will_qos) {
        connflags |= ((flags_set->will_qos & 0x3) << 3);
    }
    if (flags_set->will_retain) {
        connflags |= CONN_FLAG_WILL_RETAIN;
    }
    if (flags_set->password_flag) {
        connflags |= CONN_FLAG_PASSWORD;
    }
    if (flags_set->username_flag) {
        connflags |= CONN_FLAG_USER_NAME;
    }
    return connflags;
}

int decode_connect_flags(uint8_t connflags, conn_flags *flags_set)
{
    flags_set->clean_session =
        ((connflags & CONN_FLAG_CLEAN_SESSION) > 0) ? 1 : 0;
    flags_set->will_flag =
        ((connflags & CONN_FLAG_WILL_FLAG) == CONN_FLAG_WILL_FLAG) ? 1 : 0;
    flags_set->will_qos = ((connflags & CONN_FLAG_WILL_QOS) >> 3);
    flags_set->will_retain =
        ((connflags & CONN_FLAG_WILL_RETAIN) == CONN_FLAG_WILL_RETAIN) ? 1 : 0;
    flags_set->password_flag =
        ((connflags & CONN_FLAG_PASSWORD) == CONN_FLAG_PASSWORD) ? 1 : 0;
    flags_set->username_flag =
        ((connflags & CONN_FLAG_USER_NAME) == CONN_FLAG_USER_NAME) ? 1 : 0;

    return 0;
}

int is_clean_session(uint8_t connflags)
{
    return ((connflags & CONN_FLAG_CLEAN_SESSION) > 0) ? 1 : 0;
}

int is_will_retain(uint8_t connflags)
{
    return ((connflags & CONN_FLAG_WILL_RETAIN) == CONN_FLAG_WILL_RETAIN) ? 1
                                                                          : 0;
}

uint8_t will_qos(uint8_t connflags)
{
    return ((connflags & CONN_FLAG_WILL_QOS) >> 3);
}

int is_connection_control_msg(mqtt_packet_type packtype)
{
    int result = 0;
    switch (packtype) {
    case MQTT_CONNECT:
    case MQTT_CONNACK:
    case MQTT_PINGREQ:
    case MQTT_PINGRESP:
    case MQTT_DISCONNECT:
        result = 1;
        break;
    default:
        break;
    }
    return result;
}

int is_request_type_app_msg(mqtt_packet_type packtype)
{
    int result = 0;
    switch (packtype) {
    case MQTT_PUBLISH:
    case MQTT_SUBSCRIBE:
    case MQTT_UNSUBSCRIBE:
        result = 1;
        break;
    default:
        break;
    }
    return result;
}

int is_application_msg(mqtt_packet_type packtype, int *isrequest)
{
    int result = 0;
    *isrequest = 0;
    switch (packtype) {
    case MQTT_PUBLISH:
    case MQTT_SUBSCRIBE:
    case MQTT_UNSUBSCRIBE:
    case MQTT_PUBREL:
        result     = 1;
        *isrequest = 1;
        break;

    case MQTT_PUBACK:
    case MQTT_PUBREC:
    case MQTT_PUBCOMP:
    case MQTT_SUBACK:
        result = 1;
        break;
    default:
        break;
    }
    return result;
}

int is_packet_identifier_included(mqtt_fixed_hdr fixed_hdr)
{
    /* Mqtt 3.1.1: SUBSCRIBE, UNSUBSCRIBE, and PUBLISH (in cases where QoS > 0)
     * Control Packets MUST contain a non-zero 16-bit Packet Identifier
     */
    switch (fixed_hdr.common.packet_type) {
    case MQTT_SUBSCRIBE:
    case MQTT_SUBACK:
    case MQTT_UNSUBSCRIBE:
    case MQTT_UNSUBACK:
    case MQTT_PUBACK:
    case MQTT_PUBREC:
    case MQTT_PUBREL:
    case MQTT_PUBCOMP:
        return 1;

    case MQTT_PUBLISH: {
        if (fixed_hdr.pub.qos > 0) {
            return 1;
        }
        return 0;
    }

    default:
        break;
    }
    return 0;
}

/*============================================================================
 * Message encode
 *===========================================================================*/

int encode_connect_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    uint8_t connflags = 0;
    int     poslength = 6; /* 'length' part of Protocol Name(2) +
                              Protocol Level/Version(1) +
                              Connect Flags(1) +
                              Keep Alive(2) */

    mqtt_connect_vhdr *vhdr = &msg->var_header.connect_vh;

    /* length of protocol-name (consider "MQTT" by default */
    poslength +=
        (vhdr->protocol_name.length == 0) ? 4 : vhdr->protocol_name.length;

    /* add the length of payload part */
    mqtt_connect_payload *payload = &msg->payload.connect;
    /* client identifier. 0 length of client identifier may be allowed (in this
     * case, server may produce a client identifier to identify the client
     * internally)
     */
    poslength += 2 + payload->client_id.length; /* '2' is for length field */

    /* Will Topic */
    if (payload->will_topic.length > 0) {
        poslength += 2 + payload->will_topic.length;
        connflags |= CONN_FLAG_WILL_FLAG;
    }
    /* Will Message */
    if (payload->will_msg.length > 0) {
        poslength += 2 + payload->will_msg.length;
        connflags |= CONN_FLAG_WILL_FLAG;
    }
    /* User Name */
    if (payload->user_name.length > 0) {
        poslength += 2 + payload->user_name.length;
        connflags |= CONN_FLAG_USER_NAME;
    }
    /* Password */
    if (payload->password.length > 0) {
        poslength += 2 + payload->password.length;
        connflags |= CONN_FLAG_PASSWORD;
    }
    msg->remaining_length = poslength;
    if (msg->remaining_length > MQTT_MAX_MSG_LEN) {
        return MQTT_ERR_PAYLOAD_SIZE;
    }
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;

    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    write_byte(MQTT_CONNECT, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Protocol Name */
    if (vhdr->protocol_name.length == 0) {
        vhdr->protocol_name.str    = (unsigned char *) "MQTT";
        vhdr->protocol_name.length = 4;
    }
    write_byte_string(&vhdr->protocol_name, &buf);

    /* Protocol Level/Version */
    write_byte(vhdr->protocol_level, &buf);

    /* Connect Flags */
    write_byte(*(uint8_t *) &vhdr->conn_flags, &buf);

    /* Keep Alive */
    write_uint16(vhdr->keep_alive, &buf);

    /* Now we are in payload part */

    /* Client Identifier */
    /* Client Identifier is mandatory */
    write_byte_string(&payload->client_id, &buf);

    /* Will Topic */
    if (payload->will_topic.length) {
        if (!(vhdr->conn_flags.will_flag)) {
            return MQTT_ERR_PROTOCOL;
        }
        write_byte_string(&payload->will_topic, &buf);
    } else {
        if (vhdr->conn_flags.will_flag) {
            return MQTT_ERR_PROTOCOL;
        }
    }

    /* Will Message */
    if (payload->will_msg.length) {
        if (!(vhdr->conn_flags.will_flag)) {
            return MQTT_ERR_PROTOCOL;
        }
        write_byte_string(&payload->will_msg, &buf);
    } else {
        if (vhdr->conn_flags.will_flag) {
            return MQTT_ERR_PROTOCOL;
        }
    }

    /* User-Name */
    if (payload->user_name.length) {
        if (!(vhdr->conn_flags.username_flag)) {
            return MQTT_ERR_PROTOCOL;
        }
        write_byte_string(&payload->user_name, &buf);
    } else {
        if (vhdr->conn_flags.username_flag) {
            return MQTT_ERR_PROTOCOL;
        }
    }

    /* Password */
    if (payload->password.length) {
        if (!(vhdr->conn_flags.password_flag)) {
            return MQTT_ERR_PROTOCOL;
        }
        write_byte_string(&payload->password, &buf);
    } else {
        if (vhdr->conn_flags.password_flag) {
            return MQTT_ERR_PROTOCOL;
        }
    }

    return MQTT_SUCCESS;
}

int encode_connack_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* ConnAck Flags(1) + Connect Return Code(1) */

    mqtt_connack_vhdr *vhdr = &msg->var_header.connack_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    write_byte(MQTT_CONNACK, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Connect Acknowledge Flags */
    write_byte(vhdr->connack_flags, &buf);

    /* Connect Return Code */
    write_byte(vhdr->conn_return_code, &buf);

    return MQTT_SUCCESS;
}

int encode_subscribe_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 0;

    poslength += 2; /* for Packet Identifier */

    mqtt_subscribe_payload *spld = &msg->payload.subscribe;

    /* Go through topic filters to calculate length information */
    for (size_t i = 0; i < spld->topic_count; i++) {
        mqtt_topic *topic = &spld->topics[i];
        poslength += topic->topic_filter.length;
        poslength += 1; // for 'options' byte
        poslength += 2; // for 'length' field of Topic Filter, which is encoded
                        // as UTF-8 encoded strings */
    }

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_SUBSCRIBE;
    msg->fixed_hdr.common.bit_1       = 1;

    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    mqtt_subscribe_vhdr *vhdr = &msg->var_header.subscribe_vh;
    /* Packet Id */
    write_uint16(vhdr->packet_id, &buf);

    /* Subscribe topics */
    for (size_t i = 0; i < spld->topic_count; i++) {
        mqtt_topic *topic = &spld->topics[i];
        write_byte_string(&topic->topic_filter, &buf);
        write_byte(topic->qos, &buf);
    }

    return MQTT_SUCCESS;
}

int encode_suback_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_suback_vhdr *   vhdr = &msg->var_header.suback_vh;
    mqtt_suback_payload *spld = &msg->payload.suback;

    poslength += spld->retcode_count;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_SUBACK;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    for (uint32_t i = 0; i < spld->retcode_count; i++) {
        write_byte(spld->return_codes[i], &buf);
    }

    return MQTT_SUCCESS;
}

int encode_publish_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 0;

    poslength += 2; /* for Topic Name length field */
    poslength += msg->var_header.publish_vh.topic_name.length;
    /* Packet Identifier is requested if QoS>0 */
    if (msg->fixed_hdr.pub.qos > 0) {
        poslength += 2; /* for Packet Identifier */
    }
    poslength += msg->payload.publish.payload.length;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.pub.packet_type = MQTT_PUBLISH;
    write_byte(*(uint8_t *) &msg->fixed_hdr.pub, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    mqtt_publish_vhdr *vhdr = &msg->var_header.publish_vh;

    /* Topic Name */
    write_byte_string(&vhdr->topic_name, &buf);

    if (msg->fixed_hdr.pub.qos > 0) {
        /* Packet Id */
        write_uint16(vhdr->packet_id, &buf);
    }

    /* Payload */
    if (msg->payload.publish.payload.length > 0) {
        memcpy(buf.curpos, msg->payload.publish.payload.str,
               msg->payload.publish.payload.length);
        msg->payload.publish.payload.str =
            buf.curpos; /* reset data position to indicate data in raw data
                           block */
    }

    return MQTT_SUCCESS;
}

int encode_puback_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_puback_vhdr *vhdr = &msg->var_header.puback_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    write_byte(*(uint8_t *) &msg->fixed_hdr.pub, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    return MQTT_SUCCESS;
}

int encode_pubrec_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_pubrec_vhdr *vhdr = &msg->var_header.pubrec_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    write_byte(*(uint8_t *) &msg->fixed_hdr.pub, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    return MQTT_SUCCESS;
}

int encode_pubrel_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_pubrel_vhdr *vhdr = &msg->var_header.pubrel_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.bit_1       = 1;
    msg->fixed_hdr.common.packet_type = MQTT_PUBREL;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    return MQTT_SUCCESS;
}

int encode_pubcomp_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_pubcomp_vhdr *vhdr = &msg->var_header.pubcomp_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_PUBCOMP;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    return MQTT_SUCCESS;
}

int encode_unsubscribe_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 0;

    poslength += 2; /* for Packet Identifier */

    mqtt_unsubscribe_payload *uspld = &msg->payload.unsubscribe;

    /* Go through topic filters to calculate length information */
    for (size_t i = 0; i < uspld->topic_count; i++) {
        mqtt_str_t *topic = &uspld->topics[i];
        poslength += topic->length;
        poslength += 2; // for 'length' field of Topic Filter, which is encoded
                        // as UTF-8 encoded strings */
    }

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_UNSUBSCRIBE;
    msg->fixed_hdr.common.bit_1       = 1;

    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    mqtt_subscribe_vhdr *vhdr = &msg->var_header.subscribe_vh;
    /* Packet Id */
    write_uint16(vhdr->packet_id, &buf);

    /* Subscribe topics */
    for (size_t i = 0; i < uspld->topic_count; i++) {
        mqtt_str_t *topic = &uspld->topics[i];
        write_byte_string(topic, &buf);
    }

    return MQTT_SUCCESS;
}

int encode_unsuback_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 2; /* for Packet Identifier */

    mqtt_unsuback_vhdr *vhdr = &msg->var_header.unsuback_vh;

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_UNSUBACK;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    /* Packet Identifier */
    write_uint16(vhdr->packet_id, &buf);

    return MQTT_SUCCESS;
}

int encode_pingreq_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 0; /* No additional information included in PING message */

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_PINGREQ;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    return MQTT_SUCCESS;
}

int encode_pingresp_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength = 0; /* No additional information included in PING message */

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_PINGRESP;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    return MQTT_SUCCESS;
}

int encode_disconnect_msg(mqtt_msg *msg)
{
    /* we try to calculate the length of the possible raw data by using the
     * provided data */
    int poslength =
        0; /* No additional information included in DISCONNECT message */

    msg->remaining_length = poslength;
    uint32_t hdrlen =
        byte_number_for_variable_length(msg->remaining_length) + 1;
    uint32_t totallength = poslength + hdrlen;

    msg->entire_raw_msg.length = totallength;
    msg->entire_raw_msg.str    = (unsigned char *) malloc(totallength);
    memset(msg->entire_raw_msg.str, 0, msg->entire_raw_msg.length);

    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[0];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    msg->fixed_hdr.common.packet_type = MQTT_DISCONNECT;
    write_byte(*(uint8_t *) &msg->fixed_hdr.common, &buf);

    /* Remaining Length */
    msg->used_bytes = write_variable_length_value(poslength, &buf);

    return MQTT_SUCCESS;
}

typedef struct {
    mqtt_packet_type packet_type;
    int (*encode)(mqtt_msg *);
} mqtt_msg_encode_handler;

mqtt_msg_encode_handler encode_handlers[] = {

    { MQTT_CONNECT, encode_connect_msg },
    { MQTT_CONNACK, encode_connack_msg },
    { MQTT_PUBLISH, encode_publish_msg },
    { MQTT_PUBACK, encode_puback_msg },
    { MQTT_PUBREC, encode_pubrec_msg },
    { MQTT_PUBREL, encode_pubrel_msg },
    { MQTT_PUBCOMP, encode_pubcomp_msg },
    { MQTT_SUBSCRIBE, encode_subscribe_msg },
    { MQTT_SUBACK, encode_suback_msg },
    { MQTT_UNSUBSCRIBE, encode_unsubscribe_msg },
    { MQTT_UNSUBACK, encode_unsuback_msg },
    { MQTT_PINGREQ, encode_pingreq_msg },
    { MQTT_PINGRESP, encode_pingresp_msg },
    { MQTT_DISCONNECT, encode_disconnect_msg }

};

int mqtt_msg_encode(mqtt_msg *msg)
{
    if (!msg) {
        return MQTT_ERR_INVAL;
    }

    for (size_t i = 0;
         i < sizeof(encode_handlers) / sizeof(mqtt_msg_encode_handler); i++) {
        if (encode_handlers[i].packet_type ==
            msg->fixed_hdr.common.packet_type) {
            return encode_handlers[i].encode(msg);
        }
    }

    return MQTT_ERR_PROTOCOL;
}

/*****************************************************************************
 *    Parser Part
 *****************************************************************************/
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
    if ((buf->endpos - buf->curpos) < sizeof(uint16_t)) {
        return MQTT_ERR_INVAL;
    }

    *val = *(buf->curpos++) << 8; /* MSB */
    *val |= *(buf->curpos++);     /* LSB */

    return 0;
}

int read_utf8_str(struct pos_buf *buf, mqtt_str_t *val)
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
        val->str = buf->curpos;
        buf->curpos += length;
    } else {
        val->str = NULL;
    }
    return 0;
}

int read_str_data(struct pos_buf *buf, mqtt_str_t *val)
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
        val->str = buf->curpos;
        buf->curpos += length;
    } else {
        val->str = NULL;
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

/* A public utility function providing integer values encoded as variable-int
 * form, such as remaining-length value in the header of MQTT message. '*value'
 * returns the value of variable-int, while '*pos' returns byte number used to
 * encode that integer.
 */
int mqtt_msg_read_variable_int(unsigned char *ptr, uint32_t length,
                               uint32_t *value, uint8_t *pos)
{
    int            i;
    uint8_t        byte;
    int            multiplier = 1;
    int32_t        lword      = 0;
    uint8_t        lbytes     = 0;
    unsigned char *start      = ptr;

    if (!ptr) {
        return MQTT_ERR_PAYLOAD_SIZE;
    }
    for (i = 0; i < 4; i++) {
        if ((ptr - start + 1) > length) {
            return MQTT_ERR_PAYLOAD_SIZE;
        }
        lbytes++;
        byte = ptr[0];
        lword += (byte & 127) * multiplier;
        multiplier *= 128;
        ptr++;
        if ((byte & 128) == 0) {
            if (lbytes > 1 && byte == 0) {
                /* Catch overlong encodings */
                return MQTT_ERR_INVAL;
            } else {
                *value = lword;
                if (pos) {
                    (*pos) = lbytes;
                }
                return MQTT_SUCCESS;
            }
        } else {
            // return MQTT_ERR_INVAL;
        }
    }
    return MQTT_ERR_INVAL;
}

int get_packet_identifier(unsigned char *rawdata, uint32_t length,
                          uint8_t prebytes, uint16_t *packid)
{
    *packid = 0;

    mqtt_fixed_hdr fixed_hdr;

    memcpy((uint8_t *) &fixed_hdr, rawdata, 1);

    if (is_packet_identifier_included(fixed_hdr) == 0) {
        return MQTT_ERR_NOT_FOUND;
    }
    if (fixed_hdr.pub.packet_type == MQTT_PUBLISH) {
        if (fixed_hdr.pub.qos > 0) {
            /* We need to skip topic */
            struct pos_buf buf;
            buf.curpos = &rawdata[prebytes];
            buf.endpos = &rawdata[length];
            uint16_t topiclen;
            if (read_uint16(&buf, &topiclen) == 0) {
                buf.curpos = &rawdata[prebytes + topiclen + 2];
                return read_uint16(&buf, packid);
            } else {
                return MQTT_ERR_INVAL;
            }
        }
    } else {
        /* For all other message/packet types, including packid, the position of
         * it is the same */
        struct pos_buf buf;
        buf.curpos = &rawdata[prebytes];
        buf.endpos = &rawdata[length];
        return read_uint16(&buf, packid);
    }
    return MQTT_ERR_NOT_FOUND;
}

// int decode_publish_flags(uint8_t flags, mqtt_publish_fixed_hdr_flags
// *flags_set)
// {
//     flags_set->dup    = flags & PK_PUBLISH_FLAG_DUP;
//     flags_set->retain = flags & PK_PUBLISH_FLAG_RETAIN;
//     flags_set->qos    = ((flags & PK_PUBLISH_QOS) >> 1);

//     return 0;
// }

// int set_dup_flag(unsigned char *rawdata, uint32_t length)
// {
//     uint8_t packtype = (rawdata[0] & 0xf0);
//     if (packtype == MQTT_PUBLISH) {
//         rawdata[0] |= PK_PUBLISH_FLAG_DUP;
//     }
//     return 0;
// }

// uint8_t get_publish_qos(uint8_t packflags)
// {
//     return ((packflags & PK_PUBLISH_QOS) >> 1);
// }

// int reset_publish_qos(unsigned char *rawdata, uint32_t length, uint8_t
// new_qos)
// {
//     if (rawdata == NULL) {
//         return 1;
//     }
//     uint8_t QoS = 3; /* to clear qos bits */
//     rawdata[0] &= (~((QoS & 0x3) << 1));
//     rawdata[0] |= ((new_qos & 0x3) << 1);

//     return 0;
// }

mqtt_msg *decode_raw_packet_connect_msg(unsigned char *packet, uint32_t length,
                                        mqtt_fixed_hdr fixed_hdr,
                                        uint32_t remlength, uint8_t prebytes,
                                        uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;
    int        ret;
    conn_flags connflags = { 0 };

    mqtt_msg *msg = mqtt_msg_create_empty();

    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Protocol Name */
    ret = read_str_data(&buf, &msg->var_header.connect_vh.protocol_name);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    /* Protocol Level */
    ret = read_byte(&buf, &msg->var_header.connect_vh.protocol_level);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    /* Protocol Level */
    ret = read_byte(&buf, (uint8_t *) &msg->var_header.connect_vh.conn_flags);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    /* Keep Alive */
    ret = read_uint16(&buf, &msg->var_header.connect_vh.keep_alive);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    /* Client Identifier */
    ret = read_utf8_str(&buf, &msg->payload.connect.client_id);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    if (connflags.will_flag) {
        /* Will Topic */
        ret = read_utf8_str(&buf, &msg->payload.connect.will_topic);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
        /* Will Message */
        ret = read_str_data(&buf, &msg->payload.connect.will_msg);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
    }
    if (connflags.username_flag) {
        /* Will Topic */
        ret = read_utf8_str(&buf, &msg->payload.connect.user_name);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
    }
    if (connflags.password_flag) {
        /* Will Topic */
        ret = read_str_data(&buf, &msg->payload.connect.password);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
    }

    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_connack_msg(unsigned char *packet, uint32_t length,
                                        mqtt_fixed_hdr fixed_hdr,
                                        uint32_t remlength, uint8_t prebytes,
                                        uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Variable Header part */
    /* The variable header for the CONNACK Packet consists of two fields in the
       following order:
       - ConnAck Flags, and
       - Return Code.
     */

    /* Connack Flags */
    int result = read_byte(&buf, &msg->var_header.connack_vh.connack_flags);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    /* Connect Return Code */
    result = read_byte(&buf, &msg->var_header.connack_vh.connack_flags);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_subscribe_msg(unsigned char *packet,
                                          uint32_t       length,
                                          mqtt_fixed_hdr fixed_hdr,
                                          uint32_t remlength, uint8_t prebytes,
                                          uint32_t *parse_error,
                                          int       attached_raw)
{
    *parse_error                     = MQTT_SUCCESS;
    int            ret               = 0;
    unsigned char *saved_current_pos = NULL;
    uint16_t       temp_length       = 0;
    uint32_t       topic_count       = 0;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    mqtt_subscribe_payload *spld = &msg->payload.subscribe;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Packet Identifier */
    ret = read_uint16(&buf, &msg->var_header.subscribe_vh.packet_id);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    /* The loop to determine the number of topics.
     * TODO: Some other way may be used such as std::vector to collect topics
     * but there is a question that which is faster
     */
    /* Save the current position to back */
    saved_current_pos = buf.curpos;
    while (buf.curpos < buf.endpos) {
        ret = read_uint16(&buf, &temp_length);
        /* jump to the end of topic-name */
        buf.curpos += temp_length;
        /* skip QoS field */
        buf.curpos++;
        topic_count++;
    }

#ifdef USE_STATIC_ARRAY
    if (topic_count > MAX_TOPICS) {
        *parse_error = MQTT_ERR_NOMEM;
        goto ERROR;
    }
#else
    /* Allocate topic array */
    spld->topics = (mqtt_topic *) malloc(topic_count * sizeof(mqtt_topic));
#endif
    /* Set back current position */
    buf.curpos = saved_current_pos;
    while (buf.curpos < buf.endpos) {
        /* Topic Name */
        ret =
            read_utf8_str(&buf, &spld->topics[spld->topic_count].topic_filter);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
        /* QoS */
        ret = read_byte(&buf, &spld->topics[spld->topic_count].qos);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
        spld->topic_count++;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_suback_msg(unsigned char *packet, uint32_t length,
                                       mqtt_fixed_hdr fixed_hdr,
                                       uint32_t remlength, uint8_t prebytes,
                                       uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;
    uint8_t *ptr = NULL;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Suback Packet-Id */
    int result = read_uint16(&buf, &msg->var_header.suback_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    /* Suback Return Codes */
    msg->payload.suback.retcode_count = buf.endpos - buf.curpos;
#ifdef USE_STATIC_ARRAY
    if (msg->payload.suback.retcode_count > MAX_TOPICS) {
        *parse_error = MQTT_ERR_NOMEM;
        goto ERROR;
    }
#else
    msg->payload.suback.return_codes =
        (uint8_t *) malloc(msg->payload.suback.retcode_count * sizeof(uint8_t));
#endif
    ptr = msg->payload.suback.return_codes;
    for (uint32_t i = 0; i < msg->payload.suback.retcode_count; i++) {
        result = read_byte(&buf, ptr);
        if (result != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        } else {
        }
        ptr++;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_publish_msg(unsigned char *packet, uint32_t length,
                                        mqtt_fixed_hdr fixed_hdr,
                                        uint32_t remlength, uint8_t prebytes,
                                        uint32_t *parse_error, int attached_raw)
{
    *parse_error      = MQTT_SUCCESS;
    int ret           = 0;
    int packid_length = 0;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.pub, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Topic Name */
    ret = read_utf8_str(&buf, &msg->var_header.publish_vh.topic_name);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    if (fixed_hdr.pub.qos > MQTT_QOS_0_AT_MOST_ONCE) {
        /* Packet Identifier */
        ret = read_uint16(&buf, &msg->var_header.publish_vh.packet_id);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
        packid_length = 2;
    }

    /* Payload */
    /* No length information for payload. The length of the payload can be
       calculated by subtracting the length of the variable header from the
       Remaining Length field that is in the Fixed Header. It is valid for a
       PUBLISH Packet to contain a zero length payload.*/
    msg->payload.publish.payload.length = msg->remaining_length -
        (2 /* Length bytes of Topic Name */ +
         msg->var_header.publish_vh.topic_name.length + packid_length);
    msg->payload.publish.payload.str =
        (msg->payload.publish.payload.length > 0) ? buf.curpos : NULL;

    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_puback_msg(unsigned char *packet, uint32_t length,
                                       mqtt_fixed_hdr fixed_hdr,
                                       uint32_t remlength, uint8_t prebytes,
                                       uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    int result = read_uint16(&buf, &msg->var_header.puback_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_pubrec_msg(unsigned char *packet, uint32_t length,
                                       mqtt_fixed_hdr fixed_hdr,
                                       uint32_t remlength, uint8_t prebytes,
                                       uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    int result = read_uint16(&buf, &msg->var_header.pubrec_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_pubrel_msg(unsigned char *packet, uint32_t length,
                                       mqtt_fixed_hdr fixed_hdr,
                                       uint32_t remlength, uint8_t prebytes,
                                       uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    int result = read_uint16(&buf, &msg->var_header.pubrel_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_pubcomp_msg(unsigned char *packet, uint32_t length,
                                        mqtt_fixed_hdr fixed_hdr,
                                        uint32_t remlength, uint8_t prebytes,
                                        uint32_t *parse_error, int attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    int result = read_uint16(&buf, &msg->var_header.pubcomp_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *
decode_raw_packet_unsubscribe_msg(unsigned char *packet, uint32_t length,
                                  mqtt_fixed_hdr fixed_hdr, uint32_t remlength,
                                  uint8_t prebytes, uint32_t *parse_error,
                                  int attached_raw)
{
    *parse_error                     = MQTT_SUCCESS;
    int            ret               = 0;
    unsigned char *saved_current_pos = NULL;
    uint16_t       temp_length       = 0;
    uint32_t       topic_count       = 0;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    mqtt_unsubscribe_payload *uspld = &msg->payload.unsubscribe;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Packet Identifier */
    ret = read_uint16(&buf, &msg->var_header.unsubscribe_vh.packet_id);
    if (ret != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    /* The loop to determine the number of topics.
     * TODO: Some other way may be used such as std::vector to collect topics
     * but there is a question that which is faster
     */
    /* Save the current position to back */
    saved_current_pos = buf.curpos;
    while (buf.curpos < buf.endpos) {
        ret = read_uint16(&buf, &temp_length);
        /* jump to the end of topic-name */
        buf.curpos += temp_length;
        /* skip QoS field */
        topic_count++;
    }

#ifdef USE_STATIC_ARRAY
    if (topic_count > MAX_TOPICS) {
        *parse_error = MQTT_ERR_NOMEM;
        goto ERROR;
    }
#else
    /* Allocate topic array */
    uspld->topics = (mqtt_str_t *) malloc(topic_count * sizeof(mqtt_str_t));
#endif
    /* Set back current position */
    buf.curpos = saved_current_pos;
    while (buf.curpos < buf.endpos) {
        /* Topic Name */
        ret = read_utf8_str(&buf, &uspld->topics[uspld->topic_count]);
        if (ret != 0) {
            *parse_error = MQTT_ERR_PROTOCOL;
            goto ERROR;
        }
        uspld->topic_count++;
    }
    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *decode_raw_packet_unsuback_msg(unsigned char *packet, uint32_t length,
                                         mqtt_fixed_hdr fixed_hdr,
                                         uint32_t remlength, uint8_t prebytes,
                                         uint32_t *parse_error,
                                         int       attached_raw)
{
    *parse_error = MQTT_SUCCESS;

    mqtt_msg *msg = mqtt_msg_create_empty();
    memcpy(&msg->fixed_hdr.common, &fixed_hdr, 1);

    msg->remaining_length      = remlength;
    msg->used_bytes            = prebytes - 1;
    msg->is_parser             = 1;
    msg->attached_raw          = attached_raw;
    msg->entire_raw_msg.str    = packet;
    msg->entire_raw_msg.length = length;

    /* Set the pointer where the actual data block has started. */
    struct pos_buf buf;
    buf.curpos = &msg->entire_raw_msg.str[prebytes];
    buf.endpos = &msg->entire_raw_msg.str[msg->entire_raw_msg.length];

    /* Unsuback Packet-Id */
    int result = read_uint16(&buf, &msg->var_header.unsuback_vh.packet_id);
    if (result != 0) {
        *parse_error = MQTT_ERR_PROTOCOL;
        goto ERROR;
    }

    return msg;

ERROR:
    if (msg->attached_raw) {
        free(msg->entire_raw_msg.str);
    }
    free(msg);
    return NULL;
}

mqtt_msg *mqtt_msg_decode_raw_packet_det(unsigned char *packet, uint32_t length,
                                         mqtt_fixed_hdr fixed_hdr,
                                         uint32_t remlength, uint8_t prebytes,
                                         uint32_t *parse_error,
                                         int       attached_raw)
{
    mqtt_msg *msg = NULL;
    *parse_error  = 0;
    switch (fixed_hdr.common.packet_type) {
    case MQTT_CONNECT:
        msg =
            decode_raw_packet_connect_msg(packet, length, fixed_hdr, remlength,
                                          prebytes, parse_error, attached_raw);
        break;

    case MQTT_CONNACK:
        msg =
            decode_raw_packet_connack_msg(packet, length, fixed_hdr, remlength,
                                          prebytes, parse_error, attached_raw);
        break;

    case MQTT_PUBLISH:
        msg =
            decode_raw_packet_publish_msg(packet, length, fixed_hdr, remlength,
                                          prebytes, parse_error, attached_raw);
        break;

    case MQTT_PUBACK:
        msg = decode_raw_packet_puback_msg(packet, length, fixed_hdr, remlength,
                                           prebytes, parse_error, attached_raw);
        break;

    case MQTT_PUBREC:
        msg = decode_raw_packet_pubrec_msg(packet, length, fixed_hdr, remlength,
                                           prebytes, parse_error, attached_raw);
        break;

    case MQTT_PUBREL:
        msg = decode_raw_packet_pubrel_msg(packet, length, fixed_hdr, remlength,
                                           prebytes, parse_error, attached_raw);
        break;

    case MQTT_PUBCOMP:
        msg =
            decode_raw_packet_pubcomp_msg(packet, length, fixed_hdr, remlength,
                                          prebytes, parse_error, attached_raw);
        break;

    case MQTT_SUBSCRIBE:
        msg = decode_raw_packet_subscribe_msg(packet, length, fixed_hdr,
                                              remlength, prebytes, parse_error,
                                              attached_raw);
        break;

    case MQTT_SUBACK:
        msg = decode_raw_packet_suback_msg(packet, length, fixed_hdr, remlength,
                                           prebytes, parse_error, attached_raw);
        break;

    case MQTT_UNSUBSCRIBE:
        msg = decode_raw_packet_unsubscribe_msg(packet, length, fixed_hdr,
                                                remlength, prebytes,
                                                parse_error, attached_raw);
        break;

    case MQTT_UNSUBACK:
        msg =
            decode_raw_packet_unsuback_msg(packet, length, fixed_hdr, remlength,
                                           prebytes, parse_error, attached_raw);
        break;

    case MQTT_PINGREQ:
    case MQTT_PINGRESP:
    case MQTT_DISCONNECT: {
        msg                               = mqtt_msg_create_empty();
        msg->fixed_hdr.common.packet_type = MQTT_DISCONNECT;
        msg->remaining_length             = remlength;
        msg->used_bytes                   = prebytes - 1;
        msg->is_parser                    = 1;
        msg->attached_raw                 = attached_raw;
        msg->entire_raw_msg.str           = packet;
        msg->entire_raw_msg.length        = length;
    } break;

    default:
        *parse_error = MQTT_ERR_NOT_SUPPORTED;
        break;
    }
    return msg;
}

mqtt_msg *mqtt_msg_decode_raw_packet(unsigned char *packet, uint32_t length,
                                     uint32_t *parse_error, int attached_raw)
{
    mqtt_fixed_hdr fixed_hdr;
    memcpy((uint8_t *) &fixed_hdr, packet, 1);
    uint32_t remlength = 0;
    uint8_t  count;
    int      result =
        mqtt_msg_read_variable_int((packet + 1), length, &remlength, &count);

    if (result != MQTT_SUCCESS) {
        *parse_error = MQTT_ERR_INVAL;
        return NULL;
    }
    uint8_t prebytes = count + 1;
    /* Check for length consistency */
    if (remlength != (length - prebytes)) {
        *parse_error = MQTT_ERR_MALFORMED;
        return NULL;
    }
    return mqtt_msg_decode_raw_packet_det(packet, length, fixed_hdr, remlength,
                                          prebytes, parse_error, attached_raw);
}

const char *get_packet_type_str(mqtt_packet_type packtype)
{
    static const char *packTypeNames[16] = {
        "Forbidden-0", "CONNECT",  "CONNACK",     "PUBLISH",
        "PUBACK",      "PUBREC",   "PUBREL",      "PUBCOMP",
        "SUBSCRIBE",   "SUBACK",   "UNSUBSCRIBE", "UNSUBACK",
        "PINGREQ",     "PINGRESP", "DISCONNECT",  "Forbidden-15"
    };
    if (packtype > 15) {
        packtype = 0;
    }
    return packTypeNames[packtype];
}

int mqtt_msg_dump(mqtt_msg *msg, mqtt_str_t *sb, int print_raw)
{
    int pos = 0;
    int ret = 0;

    ret =
        sprintf((char *) &sb->str[pos],
                "\n----- MQTT Message Dump -----\n"
                "Packet Type        :   %d (%s)\n"
                "Packet Flags       :   %d | %d | %d | %d\n"
                "Remaining Length   :   %d\n",
                (int) msg->fixed_hdr.common.packet_type,
                (char *) get_packet_type_str(msg->fixed_hdr.common.packet_type),
                msg->fixed_hdr.common.bit_3, msg->fixed_hdr.common.bit_2,
                msg->fixed_hdr.common.bit_1, msg->fixed_hdr.common.bit_0,
                (int) msg->remaining_length);
    if ((ret < 0) || ((pos + ret) > sb->length)) {
        return 1;
    }
    pos += ret;

    /* Print variable header part */
    switch (msg->fixed_hdr.common.packet_type) {
    case MQTT_CONNECT: {
        ret = sprintf((char *) &sb->str[pos],
                      "Protocol Name   :   %.*s\n"
                      "Protocol Level  :   %d\n"
                      "Keep Alive      :   %d\n",
                      msg->var_header.connect_vh.protocol_name.length,
                      msg->var_header.connect_vh.protocol_name.str,
                      (int) msg->var_header.connect_vh.protocol_level,
                      (int) msg->var_header.connect_vh.keep_alive);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        conn_flags flags_set = msg->var_header.connect_vh.conn_flags;

        ret = sprintf((char *) &sb->str[pos],
                      "Connect Flags:\n   "
                      "   Clean Session Flag :    %s,\n"
                      "   Will Flag          :    %s,\n"
                      "   Will Retain Flag   :    %s,\n"
                      "   Will QoS Flag      :    %d,\n"
                      "   User Name Flag     :    %s,\n"
                      "   Password Flag      :    %s\n",
                      ((flags_set.clean_session) ? "true" : "false"),
                      ((flags_set.will_flag) ? "true" : "false"),
                      ((flags_set.will_retain) ? "true" : "false"),
                      (int) flags_set.will_qos,
                      ((flags_set.username_flag) ? "true" : "false"),
                      ((flags_set.password_flag) ? "true" : "false"));
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos], "Client Identifier    : %.*s\n",
                      msg->payload.connect.client_id.length,
                      msg->payload.connect.client_id.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos], "Will Topic           : %.*s\n",
                      msg->payload.connect.will_topic.length,
                      msg->payload.connect.will_topic.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos], "Will Message         : %.*s\n",
                      msg->payload.connect.will_msg.length,
                      msg->payload.connect.will_msg.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos], "User Name            : %.*s\n",
                      msg->payload.connect.user_name.length,
                      msg->payload.connect.user_name.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos], "Password             : %.*s\n",
                      msg->payload.connect.password.length,
                      msg->payload.connect.password.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
    } break;

    case MQTT_CONNACK:
        ret = sprintf((char *) &sb->str[pos],
                      "Connack Flags      : %d\n"
                      "Connack Return-Code: %d\n",
                      (int) msg->var_header.connack_vh.connack_flags,
                      (int) msg->var_header.connack_vh.conn_return_code);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_PUBLISH: {

        ret = sprintf((char *) &sb->str[pos],
                      "Publis Flags:\n"
                      "   Retain :     %s\n"
                      "   QoS    :     %d\n"
                      "   DUP    :     %s\n",
                      ((msg->fixed_hdr.pub.retain) ? "true" : "false"),
                      msg->fixed_hdr.pub.qos,
                      ((msg->fixed_hdr.pub.dup) ? "true" : "false"));
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        ret = sprintf((char *) &sb->str[pos],
                      "Topic     : %.*s\n"
                      "Packet Id : %d\nPayload   : %.*s\n",
                      msg->var_header.publish_vh.topic_name.length,
                      msg->var_header.publish_vh.topic_name.str,
                      (int) msg->var_header.publish_vh.packet_id,
                      msg->payload.publish.payload.length,
                      msg->payload.publish.payload.str);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
    } break;

    case MQTT_PUBACK:
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.puback_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_PUBREC:
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.pubrec_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_PUBREL:
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.pubrel_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_PUBCOMP:
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.pubcomp_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_SUBSCRIBE: {
        ret = sprintf((char *) &sb->str[pos], "Packet-Id           : %d\n",
                      msg->var_header.subscribe_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        for (uint32_t i = 0; i < msg->payload.subscribe.topic_count; i++) {
            ret =
                sprintf((char *) &sb->str[pos],
                        "Topic Filter[%u]    :   %.*s\n"
                        "Requested QoS[%u]   :   %d\n",
                        i, msg->payload.subscribe.topics[i].topic_filter.length,
                        msg->payload.subscribe.topics[i].topic_filter.str, i,
                        (int) msg->payload.subscribe.topics[i].qos);
            if ((ret < 0) || ((pos + ret) > sb->length)) {
                return 1;
            }
            pos += ret;
        }
    } break;

    case MQTT_SUBACK: {
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.suback_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        for (uint32_t i = 0; i < msg->payload.suback.retcode_count; i++) {
            ret = sprintf((char *) &sb->str[pos], "Return Code[%u]: %d", i,
                          (int) msg->payload.suback.return_codes[i]);
            if ((ret < 0) || ((pos + ret) > sb->length)) {
                return 1;
            }
            pos += ret;
        }
    } break;

    case MQTT_UNSUBSCRIBE: {
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.unsubscribe_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        for (uint32_t i = 0; i < msg->payload.unsubscribe.topic_count; i++) {
            ret = sprintf((char *) &sb->str[pos], "Topic Filter[%u] :  %.*s\n",
                          i, msg->payload.unsubscribe.topics[i].length,
                          (char *) msg->payload.unsubscribe.topics[i].str);
            if ((ret < 0) || ((pos + ret) > sb->length)) {
                return 1;
            }
            pos += ret;
        }
    } break;

    case MQTT_UNSUBACK:
        ret = sprintf((char *) &sb->str[pos], "Packet-Id: %d\n",
                      msg->var_header.unsuback_vh.packet_id);
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        break;

    case MQTT_PINGREQ:
    case MQTT_PINGRESP:
        break;

    case MQTT_DISCONNECT:
        break;

    case MQTT_AUTH:
        break;
    }

    if (print_raw) {
        ret = sprintf((char *) &sb->str[pos], "Raw Message: ");
        if ((ret < 0) || ((pos + ret) > sb->length)) {
            return 1;
        }
        pos += ret;
        for (unsigned int i = 0; i < msg->entire_raw_msg.length; i++) {
            if ((i % 16) == 0) {
                sb->str[pos++] = '\n';
            }
            // else {
            //     if ((i % 4) == 0) {
            //         sb->str[pos++] = ' ';
            //     }
            // }
            ret =
                sprintf((char *) &sb->str[pos], "%02x ",
                        ((unsigned char) (msg->entire_raw_msg.str[i] & 0xff)));
            if ((ret < 0) || ((pos + ret) > sb->length)) {
                return 1;
            }
            pos += ret;
        }
        sb->str[pos++] = '\n';
        if (pos > msg->entire_raw_msg.length) {
            return 1;
        }
        sprintf((char *) &sb->str[pos], "------------------------\n");
    }
    return 0;
}
