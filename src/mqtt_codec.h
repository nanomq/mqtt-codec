
#ifndef _MQTT_CODEC_H_
#define _MQTT_CODEC_H_
/*---------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

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
typedef struct mqtt_buf_t {
    uint32_t length;
    uint8_t *buf;
} mqtt_buf;

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
    mqtt_buf   protocol_name;
    uint8_t    protocol_version;
    conn_flags conn_flags;
    uint16_t   keep_alive;
} mqtt_connect_vhdr;

typedef struct mqtt_connack_vhdr_t {
    uint8_t connack_flags;
    uint8_t conn_return_code;
} mqtt_connack_vhdr;

typedef struct mqtt_publish_vhdr_t {
    mqtt_buf topic_name;
    uint16_t packet_id;
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

typedef struct mqtt_topic_qos_t {
    mqtt_buf topic;
    uint8_t  qos;
} mqtt_topic_qos;

/*****************************************************************************
 * Payloads
 ****************************************************************************/
typedef struct {
    mqtt_buf client_id;
    mqtt_buf will_topic;
    mqtt_buf will_msg;
    mqtt_buf user_name;
    mqtt_buf password;
} mqtt_connect_payload;

typedef struct {
    mqtt_buf payload;
} mqtt_publish_payload;

typedef struct {
    mqtt_topic_qos *topic_arr; /* array of mqtt_topic_qos instances
                                  continuous in memory */
    uint32_t topic_count;      /* not included in the message itself */
} mqtt_subscribe_payload;

typedef struct {
    uint8_t *ret_code_arr;   /* array of return codes continuous in memory */
    uint32_t ret_code_count; /* not included in the message itself */
} mqtt_suback_payload;

typedef struct {
    mqtt_buf *topic_arr;   /* array of topic_arr continuous in memory */
    uint32_t  topic_count; /* not included in the message itself */
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

typedef struct mqtt_fixed_hdr_t {
    union {
        mqtt_common_hdr common;
        mqtt_pub_hdr    publish;
    };

    uint32_t remaining_length; /* up to 268,435,455 (256 MB) */
} mqtt_fixed_hdr;

typedef struct {
    /* Fixed header part */
    mqtt_fixed_hdr             fixed_header;
    union mqtt_variable_header var_header;
    union mqtt_payload         payload;

    uint8_t used_bytes : 5; /* byte count for used remainingLength
                             representation This information (combined with
                             packetType and packetFlags)  may be used to jump
                             the point where the actual data starts */

    bool is_decoded : 1;   /* message is obtained from decoded or encoded */
    bool attached_raw : 1; /* indicates if entire_raw_msg is to be owned */
    bool _unused : 1;

    mqtt_buf entire_raw_msg; /* raw representation of whole packet */
} mqtt_msg;

extern int byte_number_for_variable_length(uint32_t variable);
extern int write_variable_length_value(uint32_t value, struct pos_buf *buf);
extern int write_byte(uint8_t val, struct pos_buf *buf);
extern int write_uint16(uint16_t value, struct pos_buf *buf);
extern int write_byte_string(mqtt_buf *str, struct pos_buf *buf);

extern int read_byte(struct pos_buf *buf, uint8_t *val);
extern int read_uint16(struct pos_buf *buf, uint16_t *val);
extern int read_utf8_str(struct pos_buf *buf, mqtt_buf *val);
extern int read_str_data(struct pos_buf *buf, mqtt_buf *val);
extern int read_packet_length(struct pos_buf *buf, uint32_t *length);

extern mqtt_buf mqtt_buf_dup(const mqtt_buf *src);
extern void     mqtt_buf_free(mqtt_buf *buf);

extern mqtt_msg *mqtt_msg_create(mqtt_packet_type packet_type);
extern int       mqtt_msg_destroy(mqtt_msg *self);
extern int       mqtt_msg_dup(mqtt_msg **dest, const mqtt_msg *src);

extern int mqtt_msg_encode(mqtt_msg *msg);

extern mqtt_msg *
mqtt_msg_decode_raw_packet_det(uint8_t *packet, uint32_t length,
                               mqtt_fixed_hdr fixed_header, uint32_t remlength,
                               uint8_t prebytes, uint32_t *parse_error,
                               int attached_raw);

extern mqtt_msg *mqtt_msg_decode_raw_packet(uint8_t *packet, uint32_t length,
                                            uint32_t *parse_error,
                                            int       attached_raw);

extern int is_connection_control_msg(mqtt_packet_type packtype);
extern int is_request_type_app_msg(mqtt_packet_type packtype);
extern int is_application_msg(mqtt_packet_type packtype, int *isrequest);
extern int is_packet_identifier_included(mqtt_fixed_hdr fixed_header);

extern int get_packet_identifier(uint8_t *rawdata, uint32_t length,
                                 uint8_t prebytes, uint16_t *packid);

extern const char *get_packet_type_str(mqtt_packet_type packtype);

extern int mqtt_msg_read_variable_int(uint8_t *ptr, uint32_t length,
                                      uint32_t *value, uint8_t *pos);

extern int mqtt_msg_dump(mqtt_msg *msg, mqtt_buf *buf, bool print_bytes);

#ifdef __cplusplus
}
#endif
/*---------------------------------------------------------------------------*/
#endif /* _MQTT_CODEC_H_ */
