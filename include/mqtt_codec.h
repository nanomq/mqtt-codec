
#ifndef _MQTT_MSG_H_
#define _MQTT_MSG_H_
/*---------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

#include "mqtt_basic.h"

mqtt_msg *mqtt_msg_create_empty(void);

int mqtt_msg_destroy(mqtt_msg *self);

int mqtt_msg_encode(mqtt_msg *msg);

mqtt_msg *mqtt_msg_decode_raw_packet_det(unsigned char *packet, uint32_t length,
                                         mqtt_fixed_hdr fixed_hdr,
                                         uint32_t remlength, uint8_t prebytes,
                                         uint32_t *parse_error,
                                         int       attached_raw);

mqtt_msg *mqtt_msg_decode_raw_packet(unsigned char *packet, uint32_t length,
                                     uint32_t *parse_error, int attached_raw);

int     is_clean_session(uint8_t connflags);
int     is_will_retain(uint8_t connflags);
uint8_t will_qos(uint8_t connflags);

/* returns '1' if packtype represents a MQTT connection control message,
 * otherwise returns '0' */
int is_connection_control_msg(mqtt_packet_type packtype);
/* returns '1' if packtype represents a MQTT application request message,
 * otherwise return '0' */
int is_request_type_app_msg(mqtt_packet_type packtype);

/* provides query if message is an application message and a request,
 * Returns '1'  for application layer messages and sets 'isRequest' to 1
 * if it is a request message. */
int is_application_msg(mqtt_packet_type packtype, int *isrequest);

/* provides query if the packet types is for message that packet-identifier
 * included. 'packFlags' is to check for possible QoS value if packet is a
 * PUBLISH packet. Returns '1' if packet-identifier included, otherwise '0'.
 */
int is_packet_identifier_included(mqtt_fixed_hdr fixed_hdr);

/* utility to extract packet identifier from raw-packet if available */
int get_packet_identifier(unsigned char *rawdata, uint32_t length,
                          uint8_t prebytes, uint16_t *packid);

/* returns string representations of packet-type.Note that 'packtype' shall
 * be in range of 0-15 */
const char *get_packet_type_str(mqtt_packet_type packtype);

/* Valid for PUBLISH message */
// int decode_publish_flags(uint8_t                       flags,
//                          mqtt_publish_fixed_hdr_flags *flags_set);
/* utility function to set DUP plag on PUBLISH raw-packet */
// int     set_dup_flag(unsigned char *rawdata, uint32_t length);
// uint8_t get_publish_qos(uint8_t packflags);
/* utility to reset PUBLISH QoS value on raw-packet */
// int reset_publish_qos(unsigned char *rawdata, uint32_t length, uint8_t new_qos);

/* A public utility function providing integer values encoded as variable-int
 * form, such as remaining-length value in the header of MQTT message. '*value'
 * returns the value of variable-int, while '*pos' returns byte number used to
 * encode that integer. This function could be useful in the case of receiving
 * messages from network.
 */
int mqtt_msg_read_variable_int(unsigned char *ptr, uint32_t length,
                               uint32_t *value, uint8_t *pos);

/* Dumps string representation of message on the provided 'sb'.
 * Buffer shall be big enough to be able to cover all dumped info. */
int mqtt_msg_dump(mqtt_msg *msg, mqtt_str_t *sb, int print_raw);

#ifdef __cplusplus
}
#endif
/*---------------------------------------------------------------------------*/
#endif /* _MQTT_MSG_H_ */
