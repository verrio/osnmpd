/*
 * This file is part of the osnmpd project (https://github.com/verrio/osnmpd).
 * Copyright (C) 2016 Olivier Verriest
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <mqueue.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "snmp-agent/agent-config.h"
#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

#define MAX_MESSAGE_SIZE    2048

#define CHECK_ENC_RESULT(x,y) do { \
    int retval = (int) (x); \
    if (retval != 0) { \
        fprintf(stderr, "failed to encode %s. (return code %d)", y, retval); \
        return -1; \
    } \
} while (0)

#define CHECK_DEC_RESULT(x,y) do { \
    int retval = (int) (x); \
    if (retval != 0) { \
        fprintf(stderr, "decoding error: %s. (return code %d)", y, retval); \
        return -1; \
    } \
} while (0)

typedef enum {
    GET_DAEMON_NAME = 0x00,
    GET_VERSION = 0x01,
    GET_UPTIME = 0x02,
    GET_ENABLED_INTERFACES = 0x03,
    SET_ENABLED_INTERFACES = 0x04,
    GET_PORT = 0x05,
    SET_PORT = 0x06,
    GET_NOTIFICATION_CONFIG = 0x07,
    SET_NOTIFICATION_CONFIG = 0x08,
    GET_USER_CONFIG = 0x09,
    SET_USER_CONFIG = 0x0A,
    SET_USER_AUTH_PASSWORD = 0x0B,
    SET_USER_PRIV_PASSWORD = 0x0C,
    GET_ENGINE_ID = 0x0D,
    SET_ENGINE_ID = 0x0E
} command;

static const char *ctl_path = "/var/run/snmp/osnmpd-ctl";
static int sock = 0;
static asn1int_t req_id = 555;
static int dry_run = 0;
static uint8_t req[MAX_MESSAGE_SIZE];
static uint8_t resp[MAX_MESSAGE_SIZE];
static char hex_buf[HEX_LEN(MAX_MESSAGE_SIZE)];

static int send_request(int command, buf_t *req, buf_t *resp)
{
    req_id++;
    asn1int_t version = 0x00;
    asn1int_t command_id = command;
    uint8_t flags = dry_run ? 0x80 : 0x00;
    CHECK_ENC_RESULT(encode_TLV(req, req->size, TAG_SEQUENCE,
        FLAG_STRUCTURED), "request arguments");
    CHECK_ENC_RESULT(encode_INTEGER(req, &command_id,
        TAG_ENUMERATED, FLAG_UNIVERSAL), "command id");
    CHECK_ENC_RESULT(encode_INTEGER(req, &req_id,
        TAG_INTEGER, FLAG_UNIVERSAL), "request id");
    CHECK_ENC_RESULT(encode_BITSTRING(req, &flags), "request flags");
    CHECK_ENC_RESULT(encode_INTEGER(req, &version,
        TAG_INTEGER, FLAG_UNIVERSAL), "request version");
    CHECK_ENC_RESULT(encode_TLV(req, req->size,
        TAG_SEQUENCE, FLAG_STRUCTURED), "request wrapper");

    if (to_hex(&req->buffer[req->pos], req->size - req->pos, hex_buf, sizeof(hex_buf)) < 0) {
        fprintf(stderr, "invalid request\n");
        return -1;
    }
    fprintf(stderr, "sending request %s\n", hex_buf);

    while (req->pos < req->size) {
        ssize_t written = write(sock, &req->buffer[req->pos], req->size - req->pos);
        if (written <= 0)
            return -1;
        req->pos += written;
    }

    int r = read(sock, resp->buffer, resp->size);
    if (r <= 0) {
        fprintf(stderr, "failed to receive response\n");
        return -1;
    }
    resp->size = r;

    if (to_hex(&resp->buffer[resp->pos], resp->size - resp->pos, hex_buf, sizeof(hex_buf)) < 0) {
        fprintf(stderr, "invalid response\n");
        return -1;
    }
    fprintf(stderr, "received response %s\n", hex_buf);

    asn1raw_t tlv;
    buf_t section;
    CHECK_DEC_RESULT(decode_TLV(&tlv, resp), "request sequence parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong request tag");
    init_ibuf(&section, tlv.value, tlv.length);

    /* check version */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response version parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong version tag");
    if (decode_INTEGER(&tlv) != 0x00) {
        fprintf(stderr, "response has invalid version\n");
        return -1;
    }

    /* check flags */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response flags parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_BITSTRING, "wrong flags tag");

    /* response id */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response id parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong request id tag");
    asn1int_t response_id = decode_INTEGER(&tlv);
    if (response_id != req_id) {
        fprintf(stderr, "response ID does not match request\n");
        return -1;
    }

    /* result */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response result id parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_ENUMERATED, "wrong result tag");
    asn1int_t result = decode_INTEGER(&tlv);
    if (result != 0x00) {
        fprintf(stderr, "response contains result code %lu\n", result);
        return -1;
    }

    /* arguments */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response arguments parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong arguments tag");
    init_ibuf(&section, tlv.value, tlv.length);

    while (section.pos < section.size) {
        CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "response argument parse exception");

        switch (tlv.type) {
            case TAG_OCTETSTRING: {
                to_hex(tlv.value, tlv.length, hex_buf, sizeof(hex_buf));
                fprintf(stderr, "octet-string: %s\n", hex_buf);
                break;
            }

            case TAG_INTEGER: {
                fprintf(stderr, "integer: %"PRIi64"\n", decode_INTEGER(&tlv));
                break;
            }

            case TAG_ENUMERATED: {
                fprintf(stderr, "enum: %"PRIi64"\n", decode_INTEGER(&tlv));
                break;
            }

            case TAG_BOOLEAN: {
                fprintf(stderr, "boolean: %i\n", decode_BOOLEAN(&tlv));
                break;
            }

            default: {
                fprintf(stderr, "skipping unknown tag %"PRIu32"\n", tlv.type);
            }
        }
    }

    return 0;
}

int cmd_fetch_version_info(void)
{
    buf_t req_buf, resp_buf;

    fprintf(stderr, "fetching name\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_DAEMON_NAME, &req_buf, &resp_buf))
        return -1;

    fprintf(stderr, "fetching version\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_VERSION, &req_buf, &resp_buf))
        return -1;

    fprintf(stderr, "fetching uptime\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_UPTIME, &req_buf, &resp_buf))
        return -1;

    return 0;
}

int cmd_set_interfaces(int iface_cnt, char **ifaces)
{
    buf_t req_buf, resp_buf;

    if (iface_cnt > 0) {
        fprintf(stderr, "updating interface list\n");
        init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
        init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
        for (int i = iface_cnt - 1; i >= 0; i--) {
            CHECK_ENC_RESULT(encode_OCTET_STRING(&req_buf, (uint8_t *) ifaces[i],
                strlen(ifaces[i])), "interface arg");
        }
        if (send_request(SET_ENABLED_INTERFACES, &req_buf, &resp_buf))
            return -1;
    }

    fprintf(stderr, "fetching interface list\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_ENABLED_INTERFACES, &req_buf, &resp_buf))
        return -1;
    return 0;
}

int cmd_set_port(int port)
{
    buf_t req_buf, resp_buf;

    if (port > 0) {
        fprintf(stderr, "updating port\n");
        init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
        init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
        asn1int_t p = port;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &p,
            TAG_INTEGER, FLAG_UNIVERSAL), "port");
        if (send_request(SET_PORT, &req_buf, &resp_buf))
            return -1;
    }

    fprintf(stderr, "fetching port\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_PORT, &req_buf, &resp_buf))
        return -1;
    return 0;
}

int cmd_set_engine_id(char *engine_id_hex)
{
    buf_t req_buf, resp_buf;

    if (engine_id_hex != NULL) {
        fprintf(stderr, "updating engine id\n");
        init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
        init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
        uint8_t engine_id[MAX_MESSAGE_SIZE];
        ssize_t engine_id_len = from_hex(engine_id_hex, engine_id, sizeof(engine_id));
        if (engine_id_len < 0) {
            fprintf(stderr, "invalid engine id\n");
            return -1;
        }
        CHECK_ENC_RESULT(encode_OCTET_STRING(&req_buf, engine_id,
            engine_id_len), "engine id arg");
        if (send_request(SET_ENGINE_ID, &req_buf, &resp_buf))
            return -1;
    }

    fprintf(stderr, "fetching engine id\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_ENGINE_ID, &req_buf, &resp_buf))
        return -1;
    return 0;
}

int cmd_set_password(int slot, char *passwd, int auth)
{
    buf_t req_buf, resp_buf;

    fprintf(stderr, "updating %s password\n", auth ? "authentication" : "privacy");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    CHECK_ENC_RESULT(encode_OCTET_STRING(&req_buf, (uint8_t *) passwd,
        strlen(passwd)), "password arg");
    asn1int_t user = slot;
    CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &user,
        TAG_ENUMERATED, FLAG_UNIVERSAL), "user arg");
    if (send_request(auth ? SET_USER_AUTH_PASSWORD : SET_USER_PRIV_PASSWORD,
        &req_buf, &resp_buf))
        return -1;
    return 0;
}

int cmd_set_notification_config(TrapConfiguration *config)
{
    buf_t req_buf, resp_buf;

    if (config != NULL) {
        fprintf(stderr, "updating notification config\n");
        init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
        init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
        asn1int_t tmp;
        tmp = config->timeout;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_INTEGER, FLAG_UNIVERSAL), "timeout arg");
        tmp = config->retries;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_INTEGER, FLAG_UNIVERSAL), "retries arg");
        tmp = config->port;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_INTEGER, FLAG_UNIVERSAL), "port arg");
        CHECK_ENC_RESULT(encode_OCTET_STRING(&req_buf, (uint8_t *) config->destination,
            strlen(config->destination)), "destination arg");
        tmp = config->user;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "user arg");
        asn1bool_t bool = config->confirmed;
        CHECK_ENC_RESULT(encode_BOOLEAN(&req_buf, &bool), "confirmed arg");
        bool = config->enabled;
        CHECK_ENC_RESULT(encode_BOOLEAN(&req_buf, &bool), "enabled arg");
        if (send_request(SET_NOTIFICATION_CONFIG, &req_buf, &resp_buf))
            return -1;
    }

    fprintf(stderr, "fetching notification config\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    if (send_request(GET_NOTIFICATION_CONFIG, &req_buf, &resp_buf))
        return -1;
    return 0;
}

int cmd_set_user_config(int user, UserConfiguration *config)
{
    asn1int_t slot = user;
    buf_t req_buf, resp_buf;

    if (config != NULL) {
        fprintf(stderr, "updating user config\n");
        init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
        init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
        asn1int_t tmp = config->security_level;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "security level arg");
        tmp = config->security_model;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "security model arg");
        CHECK_ENC_RESULT(encode_OCTET_STRING(&req_buf, (uint8_t *) config->name,
            strlen(config->name)), "user name arg");
        asn1bool_t bool = config->enabled;
        CHECK_ENC_RESULT(encode_BOOLEAN(&req_buf, &bool), "enabled arg");
        tmp = user;
        CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &tmp,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "user slot arg");
        if (send_request(SET_USER_CONFIG, &req_buf, &resp_buf))
            return -1;
    }

    fprintf(stderr, "fetching user config\n");
    init_obuf(&req_buf, req, MAX_MESSAGE_SIZE);
    init_ibuf(&resp_buf, resp, MAX_MESSAGE_SIZE);
    CHECK_ENC_RESULT(encode_INTEGER(&req_buf, &slot,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "user arg");
    if (send_request(GET_USER_CONFIG, &req_buf, &resp_buf))
        return -1;
    return 0;
}

int main(int ac, char **av)
{
    int res = 0;

    fprintf(stderr, "opening socket\n");
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        fprintf(stderr, "failed to open socket\n");
        res = 1;
        goto err;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "failed to set socket options\n");
        res = 1;
        goto err;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ctl_path, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        fprintf(stderr, "failed to open socket\n");
        res = 1;
        goto err;
    }

    int opt;
    while ((opt = getopt(ac, av, "vipnuxae?")) != -1) {
        switch (opt) {
            case 'v': {
                res |= cmd_fetch_version_info();
                break;
            }

            case 'i': {
                res |= cmd_set_interfaces(ac - optind, &av[optind]);
                break;
            }

            case 'p': {
                int port = -1;
                if (ac - optind > 0) {
                    port = atoi(av[optind]);
                }
                res |= cmd_set_port(port);
                break;
            }

            case 'n': {
                if (ac - optind < 7) {
                    res |= cmd_set_notification_config(NULL);
                } else {
                    TrapConfiguration config;
                    config.enabled = atoi(av[optind]) != 0;
                    config.confirmed = atoi(av[optind + 1]) != 0;
                    config.user = atoi(av[optind + 2]);
                    config.destination = av[optind + 3];
                    config.port = atoi(av[optind + 4]);
                    config.retries = atoi(av[optind + 5]);
                    config.timeout = atoi(av[optind + 6]);
                    res |= cmd_set_notification_config(&config);
                }
                break;
            }

            case 'u': {
                if (ac - optind < 1) {
                    fprintf(stderr, "missing user slot\n");
                    goto err;
                }
                int user = atoi(av[optind]);
                if (ac - optind < 5) {
                    res |= cmd_set_user_config(user, NULL);
                } else {
                    UserConfiguration config;
                    config.enabled = atoi(av[optind + 1]) != 0;
                    config.name = av[optind + 2];
                    config.security_model = atoi(av[optind + 3]);
                    config.security_level = atoi(av[optind + 4]);
                    res |= cmd_set_user_config(user, &config);
                }
                break;
            }

            case 'x': {
                if (ac - optind < 2) {
                    fprintf(stderr, "missing user slot and/or new password\n");
                    goto err;
                }
                int user_slot = atoi(av[optind]);
                res |= cmd_set_password(user_slot, av[optind + 1], 0);
                break;
            }

            case 'a': {
                if (ac - optind < 2) {
                    fprintf(stderr, "missing user slot and/or new password\n");
                    goto err;
                }
                int user_slot = atoi(av[optind]);
                res |= cmd_set_password(user_slot, av[optind + 1], 1);
                break;
            }

            case 'e': {
                res |= cmd_set_engine_id(ac - optind > 0 ? av[optind] : NULL);
                break;
            }

            case '?':
            default: {
                fprintf(stderr, "usage: ctl-tests [vipnuxae] <arguments>*\n");
            }
        }
    }

err:
    fprintf(stderr, "closing socket\n");
    if (sock != -1) {
        shutdown(sock, SHUT_RDWR);
    }
    exit(res ? EXIT_FAILURE : EXIT_SUCCESS);
}
