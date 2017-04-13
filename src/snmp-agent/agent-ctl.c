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

#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <mqueue.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>

#include "config.h"
#include "snmp-agent/agent-ctl.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"

#define MAX_BUF_SIZE 2048

#define CHECK_INIT_RESULT(x, y) do { \
	if ((x) == (y) -1) { \
		goto init_failed; \
	} \
} while (0)

#define CHECK_ENC_RESULT(x,y,z) do { \
	int retval = (int) (x); \
	if (retval != 0) { \
		syslog(LOG_WARNING, "failed to encode %s. (return code %d)", y, retval); \
		z; \
	} \
} while (0)

#define CHECK_DEC_RESULT(x,y) do { \
	int retval = (int) (x); \
	if (retval != 0) { \
		syslog(LOG_WARNING, "decoding error: %s. (return code %d)", y, retval); \
		goto parse_error; \
	} \
} while (0)

#define SPI_VERSION 0x00
#define MAX_REQUEST_SIZE	2048

#define SOCKET_NAME     "osnmpd-ctl"

typedef enum {
    GET_DAEMON_NAME = 0x00,
    GET_VERSION = 0x01,
    GET_UPTIME = 0x02,
    GET_ENABLED_INTERFACES = 0x03,
    SET_ENABLED_INTERFACES = 0x04,
    GET_PORT = 0x05,
    SET_PORT = 0x06,
    GET_NOTIFICATION_CONFIG = 0x07, /* host, port, user and type */
    SET_NOTIFICATION_CONFIG = 0x08,
    GET_USER_CONFIG = 0x09, /* user name, status and sec config */
    SET_USER_CONFIG = 0x0A,
    SET_USER_AUTH_PASSWORD = 0x0B,
    SET_USER_PRIV_PASSWORD = 0x0C,
    GET_ENGINE_ID = 0x0D,
    SET_ENGINE_ID = 0x0E
} command;

typedef enum {
    RES_SUCCESS = 0x00,
    RES_OTHER_REASON = 0x01,
    RES_PARSE_ERROR = 0x02,
    RES_COMMAND_NOT_AVAILABLE = 0x03,
    RES_ARGUMENTS_MISSING = 0x04,
    RES_ARGUMENTS_WRONG_LENGTH = 0x05,
    RES_ARGUMENTS_WRONG_TYPE = 0x06,
    RES_ARGUMENTS_INVALID = 0x07,
    RES_NOT_ENOUGH_MEMORY = 0x09,
    RES_MISSING_FILE = 0x0A,
    RES_DISK_NOT_AVAILABLE = 0x0B,
    RES_DISK_FULL = 0x0C,
    RES_DISK_CORRUPT = 0x0D,
    RES_TEMPORARILY_UNAVAILABLE = 0x13,
    RES_HARDWARE_FAULT = 0x14,
    RES_OS_FAULT = 0x15,
    RES_REQUEST_TIMEOUT = 0x16,
    RES_NOT_IMPLEMENTED = 0x17
} result_code;

static uint8_t const generic_fail_response[] = { 0x30, 0x0f, 0x02, 0x01, 0x00,
        0x03, 0x02, 0x00, 0x00, 0x02, 0x01, 0x00, 0x0a, 0x01, 0x01, 0x30, 0x00 };

static int spi_socket = -1;
static int config_changed = 0;

static void handle_client_socket(int const);
static int execute_command(uint8_t, asn1int_t, buf_t *, buf_t *);
static int handle_request(buf_t *, buf_t *);
static int handle_request_unavailable(uint8_t, buf_t *, buf_t *);
static int handle_request_name(uint8_t, buf_t *, buf_t *);
static int handle_request_version(uint8_t, buf_t *, buf_t *);
static int handle_request_uptime(uint8_t, buf_t *, buf_t *);
static int handle_request_interfaces(uint8_t, buf_t *, buf_t *, int);
static int handle_request_port(uint8_t, buf_t *, buf_t *, int);
static int handle_request_notification_config(uint8_t, buf_t *, buf_t *, int);
static int handle_request_user_config(uint8_t, buf_t *, buf_t *, int);
static int handle_request_set_password(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int auth_password);
static int handle_request_engine_id(uint8_t, buf_t *, buf_t *, int);

/* initialize the control interface */
int init_ctl_handler(struct pollfd *poll_descriptor)
{
    mode_t prev_mask = umask(0000);
    unlink(SNMPD_RUN_PATH SOCKET_NAME);
    CHECK_INIT_RESULT(spi_socket = socket(AF_UNIX, SOCK_STREAM, 0), int);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SNMPD_RUN_PATH SOCKET_NAME, sizeof(addr.sun_path) - 1);
    CHECK_INIT_RESULT(bind(spi_socket, (struct sockaddr* ) &addr, sizeof(addr)),
            int);
    CHECK_INIT_RESULT(listen(spi_socket, 4), int);
    umask(prev_mask);

    poll_descriptor->fd = spi_socket;
    poll_descriptor->events = POLLIN;
    return 0;

init_failed:
    syslog(LOG_ERR, "ctl init failed : %s", strerror(errno));
    unlink(SNMPD_RUN_PATH SOCKET_NAME);
    return -1;
}

/* finalize the control interface */
int finish_ctl_handler(void)
{
    int err_count = 0;

    if (spi_socket != -1) {
        if (shutdown(spi_socket, SHUT_RDWR) == -1) {
            err_count++;
        }

        if (unlink(SNMPD_RUN_PATH SOCKET_NAME) == -1) {
            err_count++;
        }
    }

    return err_count > 0 ? -1 : 0;
}

void handle_ctl_request(void)
{
    struct timeval timeout;
    timeout.tv_sec = 16;
    timeout.tv_usec = 0;

    int client_socket = accept(spi_socket, NULL, NULL);
    if (client_socket == -1) {
        return;
    }
    if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout,
            sizeof(timeout)) < 0) {
        goto finish_client;
    }
    if (setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout,
            sizeof(timeout)) < 0) {
        goto finish_client;
    }

    handle_client_socket(client_socket);

    if (config_changed) {
        write_configuration();
        config_changed = 0;
    }

finish_client:
    close(client_socket);
    return;
}

static int decode_ber_length(buf_t *buffer)
{
    if (buffer->pos < 2) {
        /* missing length octets */
        return -1;
    }

    if (buffer->buffer[1] == 0x80) {
        /* no support for indefinite length */
        return -1;
    } else if ((buffer->buffer[1] & 0x7f) == buffer->buffer[1]) {
        /* short form */
        return (0x000000ff & buffer->buffer[1]) + 2;
    } else {
        /* length of length */
        int lol = 0x7f & buffer->buffer[1];
        if (buffer->pos < (uint32_t) (2 + lol)) {
            return -1;
        } else {
            int pos = 2;
            int len = 0;
            while (lol-- > 0) {
                len = (len << 8) | (0x000000ff & buffer->buffer[pos++]);
            }
            return len + pos;
        }
    }
}

static int send_response(int const fd, uint8_t const *response,
        size_t const response_len)
{
    size_t remaining = response_len;
    size_t offset = 0;

    while (remaining > 0) {
        ssize_t written = write(fd, &response[offset], remaining);
        if (written <= 0) {
            return -1;
        }

        offset += written;
        remaining -= written;
    }

    return 0;
}

static void handle_client_socket(int const client_socket)
{
    uint8_t req_buf[MAX_REQUEST_SIZE];
    uint8_t resp_buf[MAX_REQUEST_SIZE];
    buf_t request_buffer;
    init_ibuf(&request_buffer, req_buf, sizeof(req_buf));
    buf_t response_buffer;
    init_obuf(&response_buffer, resp_buf, sizeof(resp_buf));

    while (1) {
        int r = read(client_socket, &req_buf[request_buffer.pos],
        MAX_REQUEST_SIZE - request_buffer.pos);
        if (r <= 0) {
            /* client closed his end, or error occurred */
            return;
        }

        request_buffer.pos += r;

        int len = decode_ber_length(&request_buffer);
        if (len < 0 || (unsigned int) len > request_buffer.pos) {
            return;
        }

        request_buffer.size = request_buffer.pos;
        request_buffer.pos = 0;
        if (handle_request(&request_buffer, &response_buffer) == 0) {
            send_response(client_socket, &resp_buf[response_buffer.pos],
                    response_buffer.size - response_buffer.pos);
        } else {
            /* unexpected error condition occurred.  send generic error and close socket */
            send_response(client_socket, generic_fail_response,
                sizeof(generic_fail_response));
            return;
        }

        /* init for next client request */
        request_buffer.pos = 0;
        request_buffer.size = 0;
        init_obuf(&response_buffer, resp_buf, sizeof(resp_buf));
    }
}

static int handle_request(buf_t *request_buffer, buf_t *response_buffer)
{
    int dry_run = 0;
    asn1raw_t tlv;
    buf_t section;
    CHECK_DEC_RESULT(decode_TLV(&tlv, request_buffer), "request sequence parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong request tag");
    init_ibuf(&section, tlv.value, tlv.length);

    /* check version */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "request version parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong version tag");
    if (decode_INTEGER(&tlv) != SPI_VERSION) {
        asn1int_t result_code = RES_COMMAND_NOT_AVAILABLE;
        char *message = "wrong version";
        CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer, (uint8_t *) message,
                strlen(message)), "error message", return -1);
        CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
                TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
        CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result_code,
                TAG_INTEGER, FLAG_UNIVERSAL), "result_code", return -1);
        goto write_header;
    }

    /* check flags */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "request flags parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_BITSTRING, "wrong flags tag");
    dry_run = decode_BITSTRING(&tlv) & 0x80;

    /* request id */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "request id parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong request id tag");
    asn1int_t request_id = decode_INTEGER(&tlv);

    /* command */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "request command id parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_ENUMERATED, "wrong command id tag");
    asn1int_t command_id = decode_INTEGER(&tlv);

    /* arguments */
    CHECK_DEC_RESULT(decode_TLV(&tlv, &section), "request arguments parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong arguments tag");
    init_ibuf(&section, tlv.value, tlv.length);

    CHECK_ENC_RESULT(execute_command(dry_run, command_id, &section,
            response_buffer) != 0, "response", return -1);

    write_header: ;
    /* response header */
    asn1int_t version = SPI_VERSION;
    uint8_t flags = dry_run ? 0x80 : 0x00;

    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &request_id,
            TAG_INTEGER, FLAG_UNIVERSAL), "response id", return -1);
    CHECK_ENC_RESULT(encode_BITSTRING(response_buffer, &flags),
            "response flags", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &version,
            TAG_INTEGER, FLAG_UNIVERSAL), "response version", return -1);
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response wrapper", return -1);

    return 0;

parse_error:;
    asn1int_t result_code = PARSE_ERROR;
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result_code,
            TAG_INTEGER, FLAG_UNIVERSAL), "result_code", return -1);
    goto write_header;
}

static int execute_command(uint8_t dry_run, asn1int_t command_id,
        buf_t *arguments, buf_t *response_buffer)\
{
    switch (command_id) {
        case GET_DAEMON_NAME: {
            return handle_request_name(dry_run, arguments, response_buffer);
        }

        case GET_VERSION: {
            return handle_request_version(dry_run, arguments, response_buffer);
        }

        case GET_UPTIME: {
            return handle_request_uptime(dry_run, arguments, response_buffer);
        }

        case GET_ENABLED_INTERFACES: {
            return handle_request_interfaces(dry_run, arguments, response_buffer, 0);
        }

        case SET_ENABLED_INTERFACES: {
            return handle_request_interfaces(dry_run, arguments, response_buffer, 1);
        }

        case GET_PORT: {
            return handle_request_port(dry_run, arguments, response_buffer, 0);
        }

        case SET_PORT: {
            return handle_request_port(dry_run, arguments, response_buffer, 1);
        }

        case GET_NOTIFICATION_CONFIG: {
            return handle_request_notification_config(dry_run, arguments, response_buffer, 0);
        }

        case SET_NOTIFICATION_CONFIG: {
            return handle_request_notification_config(dry_run, arguments, response_buffer, 1);
        }

        case GET_USER_CONFIG: {
            return handle_request_user_config(dry_run, arguments, response_buffer, 0);
        }

        case SET_USER_CONFIG: {
            return handle_request_user_config(dry_run, arguments, response_buffer, 1);
        }

        case SET_USER_AUTH_PASSWORD: {
            return handle_request_set_password(dry_run, arguments, response_buffer, 1);
        }

        case SET_USER_PRIV_PASSWORD: {
            return handle_request_set_password(dry_run, arguments, response_buffer, 0);
        }

        case GET_ENGINE_ID: {
            return handle_request_engine_id(dry_run, arguments, response_buffer, 0);
        }

        case SET_ENGINE_ID: {
            return handle_request_engine_id(dry_run, arguments, response_buffer, 1);
        }

        default: {
            return handle_request_unavailable(dry_run, arguments, response_buffer);
        }
    }
}

static int handle_request_unavailable(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer)
{
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "empty arguments", return -1);
    asn1int_t result = RES_COMMAND_NOT_AVAILABLE;
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result, TAG_ENUMERATED,
            FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

/* returns the name of this daemon process */
static int handle_request_name(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer)
{
    asn1int_t result = RES_SUCCESS;

    if (arguments->pos != arguments->size) {
        result = RES_ARGUMENTS_INVALID;
    } else if (!dry_run) {
        CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
            (uint8_t *) PACKAGE_NAME, strlen(PACKAGE_NAME)), "daemon name", return -1);
    }

    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result, TAG_ENUMERATED,
            FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

/* returns the version of this daemon */
static int handle_request_version(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer)
{
    asn1int_t result = RES_SUCCESS;

    if (arguments->pos != arguments->size) {
        result = RES_ARGUMENTS_INVALID;
    } else if (!dry_run) {
        CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
            (uint8_t *) PACKAGE_VERSION, strlen(PACKAGE_VERSION)),
            "daemon version", return -1);
    }

    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

/* returns the time since the last restart of this daemon */
static int handle_request_uptime(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer)
{
    asn1int_t result = RES_SUCCESS;

    if (arguments->pos != arguments->size) {
        result = RES_ARGUMENTS_INVALID;
    } else {
        struct sysinfo s_info;
        int error = sysinfo(&s_info);
        if (error != 0) {
            char *err = strerror(errno);
            CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer, (uint8_t *) err,
                    strlen(err)), "error string", return -1);
            result = RES_OS_FAULT;
        } else if (!dry_run) {
            asn1int_t uptime = get_uptime() * ((int64_t) 1000);
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &uptime,
                    TAG_INTEGER, FLAG_UNIVERSAL), "uptime", return -1);
        }
    }

    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result, TAG_ENUMERATED,
            FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

/* get/set the list of interfaces on which the SNMP agent is available */
static int handle_request_interfaces(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int modify)
{
    asn1int_t result = RES_SUCCESS;

    if (modify) {
        asn1raw_t tlv;

        unsigned int pos = arguments->pos;
        int iface_count = 0;
        while (arguments->pos < arguments->size) {
            if (decode_TLV(&tlv, arguments) == -1) {
                result = RES_PARSE_ERROR;
                goto write_header;
            } else if (tlv.type != TAG_OCTETSTRING) {
                result = RES_ARGUMENTS_WRONG_TYPE;
                goto write_header;
            } else if (tlv.length < 1) {
                result = RES_ARGUMENTS_WRONG_LENGTH;
                goto write_header;
            } else {
                iface_count++;
            }
        }
        arguments->pos = pos;

        char **ifaces = malloc(sizeof(char *) * (iface_count + 1));
        if (ifaces == NULL) {
            result = RES_NOT_ENOUGH_MEMORY;
            goto write_header;
        }

        for (int i = 0; i < iface_count; i++) {
            decode_TLV(&tlv, arguments);
            ifaces[i] = malloc(sizeof(char) * (tlv.length + 1));
            if (ifaces[i] == NULL) {
                result = RES_NOT_ENOUGH_MEMORY;
                goto write_header;
            }
            memcpy(ifaces[i], tlv.value, tlv.length);
            ifaces[i][tlv.length] = '\0';
        }
        ifaces[iface_count] = NULL;

        if (!dry_run) {
            if (set_agent_interfaces(ifaces)) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        }

        for (int i = 0; i < iface_count; i++) {
            free(ifaces[i]);
        }
        free(ifaces);
    } else {
        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            char **ifaces = get_agent_interfaces();
            while (ifaces != NULL) {
                size_t len = strlen(*ifaces);
                if (len > 0)
                    CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
                        (uint8_t *) *ifaces, len), "iface string", return -1);
                ifaces++;
            }
        }
    }

write_header:
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

static int handle_request_port(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int modify)
{
    asn1int_t result = RES_SUCCESS;
    asn1raw_t tlv;

    if (modify) {
        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_INTEGER) {
            result = RES_ARGUMENTS_WRONG_TYPE;
        } else if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            if (set_agent_port(decode_INTEGER(&tlv)) != 0) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        }
    } else {
        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            asn1int_t port = get_agent_port();
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &port,
                    TAG_INTEGER, FLAG_UNIVERSAL), "agent port", return -1);
        }
    }

    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

static int handle_request_notification_config(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int modify)
{
    asn1int_t result = RES_SUCCESS;
    asn1raw_t tlv;
    TrapConfiguration trap_config;
    trap_config.destination = NULL;

    if (modify) {
        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_BOOLEAN) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.enabled = decode_BOOLEAN(&tlv);

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_BOOLEAN) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.confirmed = decode_BOOLEAN(&tlv);

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_ENUMERATED) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.user = (SnmpUserSlot) decode_INTEGER(&tlv);
        if (trap_config.user < 0 || trap_config.user >= NUMBER_OF_USER_SLOTS) {
            syslog(LOG_ERR, "Invalid notification user slot %u.", trap_config.user);
            result = RES_ARGUMENTS_INVALID;
            goto write_header;
        }

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_OCTETSTRING) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.destination = malloc(sizeof(char) * (tlv.length + 1));
        if (trap_config.destination == NULL) {
            result = RES_NOT_ENOUGH_MEMORY;
            goto write_header;
        }
        memcpy(trap_config.destination, tlv.value, tlv.length);
        trap_config.destination[tlv.length] = '\0';

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_INTEGER) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.port = decode_INTEGER(&tlv);

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_INTEGER) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.retries = decode_INTEGER(&tlv);

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_INTEGER) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        trap_config.timeout = decode_INTEGER(&tlv);

        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
            goto write_header;
        } else if (!dry_run) {
            if (set_trap_configuration(&trap_config)) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        }
    } else {
        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            TrapConfiguration *current_config = get_trap_configuration();
            asn1int_t timeout = current_config->timeout;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &timeout,
                    TAG_INTEGER, FLAG_UNIVERSAL), "trap timeout", return -1);
            asn1int_t retries = current_config->retries;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &retries,
                    TAG_INTEGER, FLAG_UNIVERSAL), "trap retries", return -1);
            asn1int_t port = current_config->port;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &port,
                    TAG_INTEGER, FLAG_UNIVERSAL), "trap port", return -1);
            CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
                    (uint8_t *) current_config->destination,
                    strlen(current_config->destination)), "trap destination", return -1);
            asn1int_t slot = current_config->user;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &slot,
                    TAG_ENUMERATED, FLAG_UNIVERSAL), "trap user slot", return -1);
            asn1bool_t confirmed = current_config->confirmed;
            CHECK_ENC_RESULT(encode_BOOLEAN(response_buffer, &confirmed),
                    "trap confirmation", return -1);
            asn1bool_t enabled = current_config->enabled;
            CHECK_ENC_RESULT(encode_BOOLEAN(response_buffer, &enabled),
                    "trap enabled", return -1);
        }
    }

write_header:
    free(trap_config.destination);
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

static int handle_request_user_config(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int modify)
{
    asn1int_t result = RES_SUCCESS;
    asn1raw_t tlv;

    if (decode_TLV(&tlv, arguments) == -1) {
        result = PARSE_ERROR;
    } else if (tlv.type != TAG_ENUMERATED) {
        result = RES_ARGUMENTS_WRONG_TYPE;
        goto write_header;
    }

    SnmpUserSlot slot = (SnmpUserSlot) decode_INTEGER(&tlv);
    if (slot < 0 || slot >= NUMBER_OF_USER_SLOTS) {
        syslog(LOG_ERR, "Invalid notification user slot %u.", slot);
        result = RES_ARGUMENTS_INVALID;
        goto write_header;
    }

    if (modify) {
        UserConfiguration user_config;

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_BOOLEAN) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        user_config.enabled = decode_BOOLEAN(&tlv);

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_OCTETSTRING) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        } else if (tlv.length >= 0x40) {
            result = RES_ARGUMENTS_WRONG_LENGTH;
            goto write_header;
        }
        char user_name[64];
        memcpy(user_name, tlv.value, tlv.length);
        user_name[tlv.length] = '\0';
        user_config.name = user_name;

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_ENUMERATED) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        user_config.security_model = (SnmpSecurityModel) decode_INTEGER(&tlv);
        if (user_config.security_model < 0
                || user_config.security_model >= NUMBER_OF_SEC_MODELS) {
            result = RES_ARGUMENTS_INVALID;
            goto write_header;
        }

        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_ENUMERATED) {
            result = RES_ARGUMENTS_WRONG_TYPE;
            goto write_header;
        }
        user_config.security_level = (SnmpSecurityLevel) decode_INTEGER(&tlv);
        if (user_config.security_level < 0
                || user_config.security_level >= NUMBER_OF_SEC_LEVELS) {
            result = RES_ARGUMENTS_INVALID;
            goto write_header;
        }

        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
            goto write_header;
        } else if (!dry_run) {
            if (set_user_configuration(&user_config)) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        }
    } else {
        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            UserConfiguration *user_config = get_user_configuration(slot);
            asn1int_t security_level = user_config->security_level;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &security_level,
                    TAG_ENUMERATED, FLAG_UNIVERSAL), "security level", return -1);
            asn1int_t security_model = user_config->security_model;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &security_model,
                    TAG_ENUMERATED, FLAG_UNIVERSAL), "security model", return -1);
            CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
                    (uint8_t *) user_config->name, strlen(user_config->name)),
                    "user name", return -1);
            asn1bool_t enabled = user_config->enabled;
            CHECK_ENC_RESULT(encode_BOOLEAN(response_buffer, &enabled),
                    "user enabled", return -1);
            asn1int_t user_slot = user_config->user;
            CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &user_slot,
                    TAG_ENUMERATED, FLAG_UNIVERSAL), "user slot", return -1);
        }
    }

write_header:
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

static int handle_request_set_password(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int auth_password)
{
    asn1int_t result = RES_SUCCESS;
    asn1raw_t tlv;

    char password[64];
    memset(password, 0, sizeof(password));

    /* parse user ID */
    if (decode_TLV(&tlv, arguments) == -1) {
        result = RES_ARGUMENTS_MISSING;
        goto write_header;
    } else if (tlv.type != TAG_ENUMERATED) {
        result = RES_ARGUMENTS_WRONG_TYPE;
        goto write_header;
    }

    SnmpUserSlot slot = (SnmpUserSlot) decode_INTEGER(&tlv);
    if (slot < 0 || slot == USER_PUBLIC || slot >= NUMBER_OF_USER_SLOTS) {
        syslog(LOG_ERR, "Invalid user slot %u.", slot);
        result = RES_ARGUMENTS_INVALID;
        goto write_header;
    }

    /* parse password */
    if (decode_TLV(&tlv, arguments) == -1) {
        result = RES_ARGUMENTS_MISSING;
        goto write_header;
    } else if (tlv.type != TAG_OCTETSTRING) {
        result = RES_ARGUMENTS_WRONG_TYPE;
        goto write_header;
    } else if (tlv.length + 1 > sizeof(password) || tlv.length < 8) {
        result = RES_ARGUMENTS_WRONG_LENGTH;
        goto write_header;
    }

    memcpy(password, tlv.value, tlv.length);

    if (arguments->pos != arguments->size) {
        result = RES_ARGUMENTS_INVALID;
        goto write_header;
    }

    if (!dry_run) {
        if (auth_password) {
            if (set_user_auth_password(slot, password) != 0) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        } else {
            if (set_user_priv_password(slot, password) != 0) {
                result = RES_OTHER_REASON;
            } else {
                config_changed = 1;
            }
        }
    }

write_header:
    memset(password, 0, sizeof(password));
    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}

static int handle_request_engine_id(uint8_t dry_run, buf_t *arguments,
        buf_t *response_buffer, int modify)
{
    asn1int_t result = RES_SUCCESS;
    asn1raw_t tlv;

    if (modify) {
        if (decode_TLV(&tlv, arguments) == -1) {
            result = RES_ARGUMENTS_MISSING;
        } else if (tlv.type != TAG_OCTETSTRING) {
            result = RES_ARGUMENTS_WRONG_TYPE;
        } else if (tlv.length + 1 > 0x20 || tlv.length < 1) {
            result = RES_ARGUMENTS_WRONG_LENGTH;
        } else if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            if (set_engine_id(tlv.value, tlv.length) != 0) {
                result = RES_OTHER_REASON;
            } else {
                reset_boot_count();
                config_changed = 1;
            }
        }
    } else {
        if (arguments->pos != arguments->size) {
            result = RES_ARGUMENTS_INVALID;
        } else if (!dry_run) {
            uint8_t *engine_id;
            size_t engine_id_len = get_engine_id(&engine_id);
            CHECK_ENC_RESULT(encode_OCTET_STRING(response_buffer,
                    engine_id, engine_id_len), "engine id", return -1);
        }
    }

    CHECK_ENC_RESULT(encode_TLV(response_buffer, response_buffer->size,
            TAG_SEQUENCE, FLAG_STRUCTURED), "response arguments", return -1);
    CHECK_ENC_RESULT(encode_INTEGER(response_buffer, &result,
            TAG_ENUMERATED, FLAG_UNIVERSAL), "result code", return -1);
    return 0;
}
