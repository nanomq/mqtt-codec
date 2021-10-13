
#ifndef _MQTT_CODEC_H_
#define _MQTT_CODEC_H_
/*---------------------------------------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

#include "mqtt_basic.h"

extern mqtt_msg *mqtt_msg_create_empty(void);

extern int mqtt_msg_destroy(mqtt_msg *self);

extern int mqtt_msg_encode(mqtt_msg *msg);

extern mqtt_msg *mqtt_msg_decode_raw_packet_det(uint8_t *packet, uint32_t length,
                                         mqtt_fixed_hdr fixed_header,
                                         uint32_t remlength, uint8_t prebytes,
                                         uint32_t *parse_error,
                                         int       attached_raw);

extern mqtt_msg *mqtt_msg_decode_raw_packet(uint8_t *packet, uint32_t length,
                                     uint32_t *parse_error, int attached_raw);

extern int is_connection_control_msg(mqtt_packet_type packtype);
extern int is_request_type_app_msg(mqtt_packet_type packtype);
extern int is_application_msg(mqtt_packet_type packtype, int *isrequest);
extern int is_packet_identifier_included(mqtt_fixed_hdr fixed_header);

extern int get_packet_identifier(uint8_t *rawdata, uint32_t length, uint8_t prebytes,
                          uint16_t *packid);

extern const char *get_packet_type_str(mqtt_packet_type packtype);

extern int mqtt_msg_read_variable_int(uint8_t *ptr, uint32_t length, uint32_t *value,
                               uint8_t *pos);

extern int mqtt_msg_dump(mqtt_msg *msg, mqtt_str_t *buf, bool print_bytes);

#ifdef __cplusplus
}
#endif
/*---------------------------------------------------------------------------*/
#endif /* _MQTT_CODEC_H_ */
