
#include "mqtt_codec.h"

#ifdef WIN32
#include <stdint.h>
#else
#include <inttypes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFSIZE 1024

void decode_test(void)
{
    uint8_t    buffer[BUFFSIZE];
    mqtt_str_t buff; // = {&buffer[0], (uint32_t)BUFFSIZE};
    buff.str    = &buffer[0];
    buff.length = BUFFSIZE;

    uint8_t connect1[] = { 0x10, 0x17, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04,
                           0x02, 0x00, 0x3c, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
                           0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74 };

    uint8_t connect2[] = {
        0x10, 0x62, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0xc6, 0x00, 0x11,
        0x00, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x32, 0x00, 0x0f, 0x77, 0x69, 0x6c, 0x6c, 0x2f, 0x74, 0x6f, 0x70, 0x69,
        0x63, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x00, 0x1b, 0x77, 0x69, 0x6c, 0x6c,
        0x20, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20,
        0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x2e, 0x2e, 0x21, 0x00,
        0x09, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x00, 0x10,
        0x31, 0x45, 0x67, 0x66, 0x2a, 0x21, 0x23, 0x24, 0x30, 0x30, 0x38, 0x73,
        0x73, 0x6a, 0x6a, 0x4c
    };

    uint8_t disconnect1[] = { 0xe0, 0x00 };

    uint8_t publish1[] = { 0x30, 0x1a, 0x00, 0x07, 0x73, 0x65, 0x6e,
                           0x73, 0x6f, 0x72, 0x73, 0x50, 0x75, 0x62,
                           0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x20,
                           0x64, 0x61, 0x74, 0x61, 0x2e, 0x2e, 0x2e };

    uint8_t publish2[] = { 0x33, 0x1c, 0x00, 0x07, 0x73, 0x65, 0x6e, 0x73,
                           0x6f, 0x72, 0x73, 0x00, 0x01, 0x50, 0x75, 0x62,
                           0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x20, 0x64,
                           0x61, 0x74, 0x61, 0x2e, 0x2e, 0x2e };

    uint8_t publish_corrupted[] = { 0x30, 0x07, 0x00, 0x07, 0x73,
                                    0x65, 0x6e, 0x73, 0x6f, 0x72,
                                    0x73, 0x00, 0x01, 0x4f, 0x4b };

    uint8_t subscribe1[] = { 0x82, 0x29, 0x00, 0x01, 0x00, 0x24, 0x2f, 0x6f,
                             0x6e, 0x65, 0x4d, 0x32, 0x4d, 0x2f, 0x72, 0x65,
                             0x73, 0x70, 0x2f, 0x43, 0x53, 0x45, 0x33, 0x34,
                             0x30, 0x39, 0x31, 0x36, 0x35, 0x2f, 0x43, 0x53,
                             0x45, 0x31, 0x35, 0x33, 0x34, 0x31, 0x32, 0x33,
                             0x2f, 0x23, 0x01 };

    uint8_t suback1[] = { 0x90, 0x03, 0x00, 0x01, 0x00 };

    uint8_t suback2[] = {
        0x90, 0x07, 0x00, 0x01, 0x02, 0x00, 0x01, 0x01, 0x80
    };

    uint8_t puback1[]  = { 0x40, 0x02, 0x00, 0x01 };
    uint8_t pubrec1[]  = { 0x50, 0x02, 0x00, 0x01 };
    uint8_t pubrel1[]  = { 0x62, 0x02, 0x00, 0x01 };
    uint8_t pubcomp1[] = { 0x70, 0x02, 0x00, 0x01 };

    uint8_t unsubscribe1[] = { 0xa2, 0x0c, 0x00, 0x01, 0x00, 0x03, 0x61,
                               0x2f, 0x62, 0x00, 0x03, 0x63, 0x2f, 0x64 };

    uint8_t unsuback1[] = { 0xb0, 0x02, 0x00, 0x01 };

    uint8_t pingreq1[]  = { 0xc0, 0x00 };
    uint8_t pingresp1[] = { 0xd0, 0x00 };

    uint32_t  parse_error = 0;
    mqtt_msg *msg         = NULL;
    /* Use attached_raw>0 to provide deallocation of raw-packet on message
     * destroy for dynamically allocated packets. Note that; this is not the
     * case for this test code since raw-packet is statically allocated, so we
     * pass 0 for attached_raw
     */
    msg =
        mqtt_msg_decode_raw_packet(connect1, sizeof(connect1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("\n*** Parse error: %d for connect1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg =
        mqtt_msg_decode_raw_packet(connect2, sizeof(connect2), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("\n*** Parse error: %d for connect2\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(disconnect1, sizeof(disconnect1),
                                     &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("\n*** Parse error: %d for disconnect1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg =
        mqtt_msg_decode_raw_packet(publish1, sizeof(publish1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("\n*** Parse error: %d for publish1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg =
        mqtt_msg_decode_raw_packet(publish2, sizeof(publish2), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for publish2\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(
        publish_corrupted, sizeof(publish_corrupted), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for publish_corrupted\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(subscribe1, sizeof(subscribe1),
                                     &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for subscribe1\n", parse_error);
    }
    if (msg) {
        free(msg->payload.subscribe.topic_arr);
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(suback1, sizeof(suback1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for suback1\n", parse_error);
    }
    if (msg) {
        free(msg->payload.suback.ret_code_arr);
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(suback2, sizeof(suback2), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for suback2\n", parse_error);
    }
    if (msg) {
        free(msg->payload.suback.ret_code_arr);
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(puback1, sizeof(puback1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for puback1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(pubrec1, sizeof(pubrec1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for pubrec1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(pubrel1, sizeof(pubrel1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for pubrel1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg =
        mqtt_msg_decode_raw_packet(pubcomp1, sizeof(pubcomp1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for pubcomp1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(unsubscribe1, sizeof(unsubscribe1),
                                     &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for unsubscribe1\n", parse_error);
    }
    if (msg) {
        free(msg->payload.unsubscribe.topic_arr);
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(unsuback1, sizeof(unsuback1), &parse_error,
                                     0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for unsuback1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg =
        mqtt_msg_decode_raw_packet(pingreq1, sizeof(pingreq1), &parse_error, 0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for pingreq1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }

    msg = mqtt_msg_decode_raw_packet(pingresp1, sizeof(pingresp1), &parse_error,
                                     0);
    if (parse_error == MQTT_SUCCESS) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(msg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Parse error: %d for pingresp1\n", parse_error);
    }
    if (msg) {
        mqtt_msg_destroy(msg);
    }
}

void encode_test(void)
{
    int        ret = 0;
    uint8_t    buffer[BUFFSIZE];
    mqtt_str_t buff; // = {&buffer[0], (uint32_t)BUFFSIZE};
    buff.str    = &buffer[0];
    buff.length = BUFFSIZE;

    /* CONNECT */
    mqtt_msg *connmsg                                = mqtt_msg_create_empty();
    connmsg->fixed_header.common.packet_type         = MQTT_CONNECT;
    connmsg->var_header.connect.protocol_name.str    = (uint8_t *) "MQTT";
    connmsg->var_header.connect.protocol_name.length = 4;
    connmsg->var_header.connect.protocol_level       = 4; // MQTT_VERSION_3_1_1;
    connmsg->var_header.connect.keep_alive           = 350;

    conn_flags connflags = { .clean_session = 1,
                             .will_retain   = 0,
                             .will_qos      = 0,
                             .will_flag     = 1,
                             .username_flag = 1,
                             .password_flag = 1 };

    connmsg->payload.connect.will_topic.str = (uint8_t *) "will_topic";
    connmsg->payload.connect.will_topic.length =
        strlen((char *) connmsg->payload.connect.will_topic.str);
    connmsg->payload.connect.will_msg.str = (uint8_t *) "bye-bye";
    connmsg->payload.connect.will_msg.length =
        strlen((char *) connmsg->payload.connect.will_msg.str);

    connmsg->payload.connect.user_name.str = (uint8_t *) "Alvin";
    connmsg->payload.connect.user_name.length =
        strlen((char *) connmsg->payload.connect.user_name.str);

    connmsg->payload.connect.password.str = (uint8_t *) "YYDS";
    connmsg->payload.connect.password.length =
        strlen((char *) connmsg->payload.connect.password.str);

    memcpy((uint8_t *) &connmsg->var_header.connect.conn_flags,
           (uint8_t *) &connflags, 1);

    connmsg->payload.connect.client_id.str = (uint8_t *) "Test-Client1";
    connmsg->payload.connect.client_id.length =
        strlen((char *) connmsg->payload.connect.client_id.str);

    ret = mqtt_msg_encode(connmsg);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(connmsg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building connect example : %d\n", ret);
    }
    mqtt_msg_destroy(connmsg);

    /* CONNACK */
    mqtt_msg *connack                            = mqtt_msg_create_empty();
    connack->fixed_header.common.packet_type     = MQTT_CONNACK;
    connack->var_header.connack.conn_return_code = 4;
    connack->var_header.connack.connack_flags |= 1;
    ret = mqtt_msg_encode(connack);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(connack, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building connack example : %d\n", ret);
    }
    mqtt_msg_destroy(connack);

    /* PUBREL */
    mqtt_msg *pubrel                        = mqtt_msg_create_empty();
    pubrel->fixed_header.common.packet_type = MQTT_PUBREL;
    pubrel->var_header.pubrel.packet_id     = 1;
    ret                                     = mqtt_msg_encode(pubrel);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pubrel, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pubrel example : %d\n", ret);
    }
    mqtt_msg_destroy(pubrel);

    /* PUBACK */
    mqtt_msg *puback                        = mqtt_msg_create_empty();
    puback->fixed_header.common.packet_type = MQTT_PUBACK;
    puback->var_header.puback.packet_id     = 2;
    ret                                     = mqtt_msg_encode(puback);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(puback, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building puback example : %d\n", ret);
    }
    mqtt_msg_destroy(puback);

    mqtt_msg *pubrec                        = mqtt_msg_create_empty();
    pubrec->fixed_header.common.packet_type = MQTT_PUBREC;
    pubrec->var_header.pubrec.packet_id     = 3;
    ret                                     = mqtt_msg_encode(pubrec);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pubrec, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pubrec example : %d\n", ret);
    }
    mqtt_msg_destroy(pubrec);

    /* PUBCOMP */
    mqtt_msg *pubcomp                        = mqtt_msg_create_empty();
    pubcomp->fixed_header.common.packet_type = MQTT_PUBCOMP;
    pubcomp->var_header.pubcomp.packet_id    = 3;
    ret                                      = mqtt_msg_encode(pubcomp);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pubcomp, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pubcomp example : %d\n", ret);
    }
    mqtt_msg_destroy(pubcomp);

    /* SUBSCRIBE */
    mqtt_msg *submsg                        = mqtt_msg_create_empty();
    submsg->fixed_header.common.packet_type = MQTT_SUBSCRIBE;

    mqtt_topic topic_arr[3];
    topic_arr[0].topic_filter.str = (uint8_t *) "sub/mqtt/1";
    topic_arr[0].topic_filter.length =
        strlen((const char *) topic_arr[0].topic_filter.str);
    topic_arr[0].qos              = 2;
    topic_arr[1].topic_filter.str = (uint8_t *) "sub/mqtt/2";
    topic_arr[1].topic_filter.length =
        strlen((const char *) topic_arr[1].topic_filter.str);
    topic_arr[1].qos              = 0;
    topic_arr[2].topic_filter.str = (uint8_t *) "sub/mqtt/3";
    topic_arr[2].topic_filter.length =
        strlen((const char *) topic_arr[2].topic_filter.str);
    topic_arr[2].qos                    = 1;
    submsg->payload.subscribe.topic_arr = &topic_arr[0];

    submsg->payload.subscribe.topic_count  = 3;
    submsg->var_header.subscribe.packet_id = 45;

    ret = mqtt_msg_encode(submsg);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(submsg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building subscribe example : %d\n", ret);
    }
    mqtt_msg_destroy(submsg);

    /* SUBACK */
    mqtt_msg *suback                        = mqtt_msg_create_empty();
    suback->fixed_header.common.packet_type = MQTT_SUBACK;
    suback->payload.suback.ret_code_count   = 3;

    suback->payload.suback.ret_code_arr =
        malloc(suback->payload.suback.ret_code_count * sizeof(uint8_t));
    suback->payload.suback.ret_code_arr[0] = 0;
    suback->payload.suback.ret_code_arr[1] = 2;
    suback->payload.suback.ret_code_arr[2] = 0x80; /* failure */
    suback->var_header.suback.packet_id    = 45;
    ret                                    = mqtt_msg_encode(suback);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(suback, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building suback example : %d\n", ret);
    }
    /* deallocate return-codes array */
    free(suback->payload.suback.ret_code_arr);
    mqtt_msg_destroy(suback);

    /* PUBLISH */
    mqtt_msg *pubmsg                          = mqtt_msg_create_empty();
    pubmsg->fixed_header.publish.packet_type  = MQTT_PUBLISH;
    pubmsg->fixed_header.publish.dup          = 0;
    pubmsg->fixed_header.publish.qos          = 2;
    pubmsg->fixed_header.publish.retain       = 0;
    pubmsg->var_header.publish.packet_id      = 876;
    pubmsg->var_header.publish.topic_name.str = (uint8_t *) "/nanomq/mqtt/msg";
    pubmsg->var_header.publish.topic_name.length =
        strlen((char *) pubmsg->var_header.publish.topic_name.str);
    pubmsg->payload.publish.payload.str =
        (uint8_t *) "{\"broker\" : \"/nanomq\",\"sdk\" : \"mqtt-codec\"}";
    pubmsg->payload.publish.payload.length =
        strlen((char *) pubmsg->payload.publish.payload.str);

    ret = mqtt_msg_encode(pubmsg);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pubmsg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pubmsg example : %d\n", ret);
    }
    mqtt_msg_destroy(pubmsg);

    /* UNSUBSCRIBE */
    mqtt_msg *unsubscribe                         = mqtt_msg_create_empty();
    unsubscribe->fixed_header.common.packet_type  = MQTT_UNSUBSCRIBE;
    unsubscribe->var_header.unsubscribe.packet_id = 46;

    mqtt_str_t untopics[2];
    untopics[0].str    = (uint8_t *) "sub/topic/1";
    untopics[0].length = strlen((char *) untopics[0].str);
    untopics[1].str    = (uint8_t *) "sub/topic/3";
    untopics[1].length = strlen((char *) untopics[1].str);
    unsubscribe->payload.unsubscribe.topic_arr = &untopics[0];

    unsubscribe->payload.unsubscribe.topic_count = 2;
    ret                                          = mqtt_msg_encode(unsubscribe);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(unsubscribe, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building unsubscribe example : %d\n", ret);
    }
    mqtt_msg_destroy(unsubscribe);

    /* UNSUBACK */
    mqtt_msg *unsuback                        = mqtt_msg_create_empty();
    unsuback->fixed_header.common.packet_type = MQTT_UNSUBACK;
    unsuback->var_header.unsuback.packet_id   = 46;
    ret                                       = mqtt_msg_encode(unsuback);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(unsuback, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building unsuback example : %d\n", ret);
    }
    mqtt_msg_destroy(unsuback);

    /* PINGREQ */
    mqtt_msg *pingreq                        = mqtt_msg_create_empty();
    pingreq->fixed_header.common.packet_type = MQTT_PINGREQ;
    ret                                      = mqtt_msg_encode(pingreq);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pingreq, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pingreq example : %d\n", ret);
    }
    mqtt_msg_destroy(pingreq);

    /* PINGRESP */
    mqtt_msg *pingresp                        = mqtt_msg_create_empty();
    pingresp->fixed_header.common.packet_type = MQTT_PINGRESP;
    ret                                       = mqtt_msg_encode(pingresp);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pingresp, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pingresp example : %d\n", ret);
    }
    mqtt_msg_destroy(pingresp);

    /* DISCONNECT */
    mqtt_msg *disconn                        = mqtt_msg_create_empty();
    disconn->fixed_header.common.packet_type = MQTT_DISCONNECT;
    ret                                      = mqtt_msg_encode(disconn);
    if (ret == 0) {
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(disconn, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building disconnect example : %d\n", ret);
    }
    mqtt_msg_destroy(disconn);
}

void test_for_mqtt_codec_encode(void)
{
    int        ret = 0;
    uint8_t    buffer[BUFFSIZE];
    mqtt_str_t buff;
    buff.str    = &buffer[0];
    buff.length = BUFFSIZE;

    char *topic_name = strdup("/nanomq/mqtt/msg");
    char *payload    = strdup("{\"name\" : \"/nanomq\",\"seq\" : 1}");

    /* PUBLISH */
    mqtt_msg *pubmsg                         = mqtt_msg_create_empty();
    pubmsg->fixed_header.publish.packet_type = MQTT_PUBLISH;
    pubmsg->fixed_header.publish.dup         = 0;
    pubmsg->fixed_header.publish.qos         = 0;
    pubmsg->fixed_header.publish.retain      = 0;

    pubmsg->var_header.publish.packet_id         = 876;
    pubmsg->var_header.publish.topic_name.str    = (uint8_t *) topic_name;
    pubmsg->var_header.publish.topic_name.length = strlen(topic_name);
    pubmsg->payload.publish.payload.str          = (uint8_t *) payload;
    pubmsg->payload.publish.payload.length       = strlen(payload);

    ret = mqtt_msg_encode(pubmsg);
    if (ret == 0) {
        /* free allocated texts to verify that now built message uses inner raw
         * data */
        free(topic_name);
        topic_name = NULL;
        free(payload);
        payload = NULL;
        memset(buff.str, 0, buff.length);
        mqtt_msg_dump(pubmsg, &buff, 1);
        printf("%s", buff.str);
    } else {
        printf("Problem on building pubmsg example : %d\n", ret);
    }
    mqtt_msg_destroy(pubmsg);
}

int main(int argc, char *argv[])
{
    decode_test();

    encode_test();

    test_for_mqtt_codec_encode();

    return 0;
}
