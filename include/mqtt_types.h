
#ifndef MQTT_TYPES_H_
#define MQTT_TYPES_H_
/*---------------------------------------------------------------------------*/
#ifdef __cplusplus
extern "C" {
#endif

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

/* CONNECT Flags */
#define CONN_FLAG_RESERVERD 0x01
#define CONN_FLAG_CLEAN_SESSION 0x02
#define CONN_FLAG_WILL_FLAG 0x04
#define CONN_FLAG_WILL_QOS 0x18
#define CONN_FLAG_WILL_RETAIN 0x20
#define CONN_FLAG_PASSWORD 0x40
#define CONN_FLAG_USER_NAME 0x80

/* CONNACK Flags */
#define CONNACK_FLAG_SESSION_PRESENT 0x01

/* Packet Flags for PUBLISH */
#define PK_PUBLISH_FLAG_DUP 0x08
#define PK_PUBLISH_QOS 0x06
#define PK_PUBLISH_FLAG_RETAIN 0x01

#ifdef __cplusplus
}
#endif

/*---------------------------------------------------------------------------*/
#endif /* MQTT_TYPES_H_ */
