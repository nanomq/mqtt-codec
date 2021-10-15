#ifndef _MQTT_BASIC_H_
#define _MQTT_BASIC_H_

#ifdef WIN32
#include <stdint.h>
#else
#include <inttypes.h>
#endif

#include <stdbool.h>

#define MQTT_VERSION_3_1 3
#define MQTT_VERSION_3_1_1 4
#define MQTT_VERSION_5_0 5

#define MQTT_PROTOCOL_NAME "MQTT"

#define MQTT_MAX_MSG_LEN 268435455

#define MQTT_MAX_LENGTH_BYTES 4
#define MQTT_LENGTH_VALUE_MASK 0x7F
#define MQTT_LENGTH_CONTINUATION_BIT 0x80
#define MQTT_LENGTH_SHIFT 7

/* Packet types */
typedef enum mqtt_packet_type_t {
    MQTT_CONNECT     = 0x01,
    MQTT_CONNACK     = 0x02,
    MQTT_PUBLISH     = 0x03,
    MQTT_PUBACK      = 0x04,
    MQTT_PUBREC      = 0x05,
    MQTT_PUBREL      = 0x06,
    MQTT_PUBCOMP     = 0x07,
    MQTT_SUBSCRIBE   = 0x08,
    MQTT_SUBACK      = 0x09,
    MQTT_UNSUBSCRIBE = 0x0A,
    MQTT_UNSUBACK    = 0x0B,
    MQTT_PINGREQ     = 0x0C,
    MQTT_PINGRESP    = 0x0D,
    MQTT_DISCONNECT  = 0x0E,
    MQTT_AUTH        = 0x0F
} mqtt_packet_type;

/* Quality of Service types. */
#define MQTT_QOS_0_AT_MOST_ONCE 0
#define MQTT_QOS_1_AT_LEAST_ONCE 1
#define MQTT_QOS_2_EXACTLY_ONCE 2

/* CONNACK codes */
#define MQTT_CONNACK_ACCEPTED 0
#define MQTT_CONNACK_REFUSED_PROTOCOL_VERSION 1
#define MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED 2
#define MQTT_CONNACK_REFUSED_SERVER_UNAVAILABLE 3
#define MQTT_CONNACK_REFUSED_BAD_USERNAME_PASSWORD 4
#define MQTT_CONNACK_REFUSED_NOT_AUTHORIZED 5

/* Function return codes */
#define MQTT_SUCCESS 0
#define MQTT_ERR_NOMEM 1
#define MQTT_ERR_PROTOCOL 2
#define MQTT_ERR_INVAL 3
#define MQTT_ERR_PAYLOAD_SIZE 4
#define MQTT_ERR_NOT_SUPPORTED 5
#define MQTT_ERR_NOT_FOUND 6
#define MQTT_ERR_MALFORMED 7

struct pos_buf {
    uint8_t *curpos;
    uint8_t *endpos;
};

/* Compact string type */
typedef struct {
    uint32_t length;
    uint8_t *str;
} mqtt_str_t;

/* CONNECT flags */
typedef struct conn_flags_t {
    uint8_t reserved : 1;
    uint8_t clean_session : 1;
    uint8_t will_flag : 1;
    uint8_t will_qos : 2;
    uint8_t will_retain : 1;
    uint8_t password_flag : 1;
    uint8_t username_flag : 1;
} conn_flags;

/*****************************************************************************
 * Variable header parts
 ****************************************************************************/
typedef struct mqtt_connect_vhdr_t {
    mqtt_str_t protocol_name;
    uint8_t    protocol_version;
    conn_flags conn_flags;
    uint16_t   keep_alive;
} mqtt_connect_vhdr;

typedef struct mqtt_connack_vhdr_t {
    uint8_t connack_flags;
    uint8_t conn_return_code;
} mqtt_connack_vhdr;

typedef struct mqtt_publish_vhdr_t {
    mqtt_str_t topic_name;
    uint16_t   packet_id;
} mqtt_publish_vhdr;

typedef struct mqtt_puback_vhdr_t {
    uint16_t packet_id;
} mqtt_puback_vhdr;

typedef struct mqtt_pubrec_vhdr_t {
    uint16_t packet_id;
} mqtt_pubrec_vhdr;

typedef struct mqtt_pubrel_vhdr_t {
    uint16_t packet_id;
} mqtt_pubrel_vhdr;

typedef struct mqtt_pubcomp_vhdr_t {
    uint16_t packet_id;
} mqtt_pubcomp_vhdr;

typedef struct mqtt_subscribe_vhdr_t {
    uint16_t packet_id;
} mqtt_subscribe_vhdr;

typedef struct mqtt_suback_vhdr_t {
    uint16_t packet_id;
} mqtt_suback_vhdr;

typedef struct mqtt_unsubscribe_vhdr_t {
    uint16_t packet_id;
} mqtt_unsubscribe_vhdr;

typedef struct mqtt_unsuback_vhdr_t {
    uint16_t packet_id;
} mqtt_unsuback_vhdr;

/*****************************************************************************
 * Union to cover all Variable Header types
 ****************************************************************************/
union mqtt_variable_header {
    mqtt_connect_vhdr     connect;
    mqtt_connack_vhdr     connack;
    mqtt_publish_vhdr     publish;
    mqtt_puback_vhdr      puback;
    mqtt_pubrec_vhdr      pubrec;
    mqtt_pubrel_vhdr      pubrel;
    mqtt_pubcomp_vhdr     pubcomp;
    mqtt_subscribe_vhdr   subscribe;
    mqtt_suback_vhdr      suback;
    mqtt_unsubscribe_vhdr unsubscribe;
    mqtt_unsuback_vhdr    unsuback;
};

typedef struct {
    mqtt_str_t topic_filter;
    uint8_t    qos;
} mqtt_topic;

/*****************************************************************************
 * Payloads
 ****************************************************************************/
typedef struct {
    mqtt_str_t client_id;
    mqtt_str_t will_topic;
    mqtt_str_t will_msg;
    mqtt_str_t user_name;
    mqtt_str_t password;
} mqtt_connect_payload;

typedef struct {
    mqtt_str_t payload;
} mqtt_publish_payload;

typedef struct {
    mqtt_topic
        *    topic_arr; /* array of mqtt_topic instances continuous in memory */
    uint32_t topic_count; /* not included in the message itself */
} mqtt_subscribe_payload;

typedef struct {
    uint8_t *ret_code_arr;   /* array of return codes continuous in memory */
    uint32_t ret_code_count; /* not included in the message itself */
} mqtt_suback_payload;

typedef struct {
    mqtt_str_t *topic_arr;   /* array of topic_arr continuous in memory */
    uint32_t    topic_count; /* not included in the message itself */
} mqtt_unsubscribe_payload;

/*****************************************************************************
 * Union to cover all Payload types
 ****************************************************************************/
union mqtt_payload {
    mqtt_connect_payload     connect;
    mqtt_publish_payload     publish;
    mqtt_subscribe_payload   subscribe;
    mqtt_suback_payload      suback;
    mqtt_unsubscribe_payload unsubscribe;
};

typedef struct {
    uint8_t          bit_0 : 1;
    uint8_t          bit_1 : 1;
    uint8_t          bit_2 : 1;
    uint8_t          bit_3 : 1;
    mqtt_packet_type packet_type : 4;
} mqtt_common_hdr;

typedef struct {
    uint8_t          retain : 1;
    uint8_t          qos : 2;
    uint8_t          dup : 1;
    mqtt_packet_type packet_type : 4;
} mqtt_pub_hdr;

typedef struct {
    union {
        mqtt_common_hdr common;
        mqtt_pub_hdr    publish;
    };

    uint32_t remaining_length; /* up to 268,435,455 (256 MB) */
} mqtt_fixed_hdr;

typedef struct {
    /* Fixed header part */
    mqtt_fixed_hdr fixed_header;

    uint8_t used_bytes; /* byte count for used remainingLength representation
                             This information (combined with packetType and
                             packetFlags)  may be used to jump the point where
                             the actual data starts */
    union mqtt_variable_header var_header;
    union mqtt_payload         payload;

    bool       is_decoded;     /* message is obtained from decoded or encoded */
    mqtt_str_t entire_raw_msg; /* raw representation of whole packet */
    int        attached_raw;   /* indicates if entire_raw_msg is to be owned */
} mqtt_msg;

extern int byte_number_for_variable_length(uint32_t variable);
extern int write_variable_length_value(uint32_t value, struct pos_buf *buf);
extern int write_byte(uint8_t val, struct pos_buf *buf);
extern int write_uint16(uint16_t value, struct pos_buf *buf);
extern int write_byte_string(mqtt_str_t *str, struct pos_buf *buf);

extern int read_byte(struct pos_buf *buf, uint8_t *val);
extern int read_uint16(struct pos_buf *buf, uint16_t *val);
extern int read_utf8_str(struct pos_buf *buf, mqtt_str_t *val);
extern int read_str_data(struct pos_buf *buf, mqtt_str_t *val);
extern int read_packet_length(struct pos_buf *buf, uint32_t *length);

#endif
