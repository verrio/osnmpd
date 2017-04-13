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

#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include "config.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/java-subagent/java-subagent.h"

#define JAVA_BUF_SIZE   2048
#define JAVA_SOCKET_TIMEOUT     10
#define JAVA_MODULE_MIB_OID     JAVA_SUB_AGENT_MIB

#define CHECK_JAVA_RESPONSE(x,y) do { \
    int retval = (x); \
    if (retval != 0) { \
        syslog(LOG_WARNING, "Java agent response error : %s", y); \
        goto err; \
    } \
} while (0)

/* socket on which the java agent can be reached */
#define JAVA_SOCKET_VERSION     0
#define JAVA_SOCKET     SNMPD_RUN_PATH "java-subagent"

static SysOREntry java_sub_agent_or_entry = {
    .or_id = {
        .subid = { JAVA_MODULE_MIB_OID },
        .len = OID_SEQ_LENGTH(JAVA_MODULE_MIB_OID)
    },
    .or_descr = "JAVA-SUB-AGENT - Java SNMP subagent",
    .next = NULL
};

#define SUB_AGENT_GET   0xC0
#define SUB_AGENT_GET_NEXT  0xC1
#define SUB_AGENT_SET   0xC2

static int create_request(buf_t *request_buffer,
        SnmpVariableBinding *binding, int type, int dry_run)
{
    if (encode_variable_binding(binding, request_buffer)) {
        return -1;
    }

    asn1int_t request_type = type;
    if (encode_INTEGER(request_buffer, &request_type,
        TAG_ENUMERATED, FLAG_UNIVERSAL)) {
        return -1;
    }

    asn1int_t request_id = 0;
    if (encode_INTEGER(request_buffer, &request_id, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }

    uint8_t flags = dry_run ? 0x80 : 0x00;
    if (encode_BITSTRING(request_buffer, &flags)) {
        return -1;
    }

    asn1int_t version = JAVA_SOCKET_VERSION;
    if (encode_INTEGER(request_buffer, &version, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }

    if (encode_TLV(request_buffer,
            request_buffer->size, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    return 0;
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

static SnmpErrorStatus send_request(SnmpVariableBinding *binding,
        int type, int dry_run)
{
    SnmpErrorStatus result = NO_ERROR;

    uint8_t req_buf[JAVA_BUF_SIZE];
    buf_t request_buffer;
    init_obuf(&request_buffer, req_buf, sizeof(req_buf));
    if (create_request(&request_buffer, binding, type, dry_run)) {
        return GENERAL_ERROR;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        goto err;
    }

    struct timeval timeout;
    timeout.tv_sec = JAVA_SOCKET_TIMEOUT;
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
        goto err;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
        goto err;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, JAVA_SOCKET, sizeof(addr.sun_path)-1);
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        goto err;

    size_t remaining = request_buffer.size - request_buffer.pos;
    while (remaining > 0) {
        ssize_t written = write(fd, &req_buf[request_buffer.pos], remaining);
        if (written <= 0) {
            goto err;
        }
        remaining -= written;
    }

    uint8_t resp_buf[JAVA_BUF_SIZE];
    buf_t response_buffer;
    init_ibuf(&response_buffer, resp_buf, sizeof(resp_buf));
    while (1) {
        int r = read(fd, &resp_buf[response_buffer.pos],
                response_buffer.size - response_buffer.pos);
        if (r <= 0) {
            syslog(LOG_WARNING, "no or incomplete response from java sub agent.");
            goto err;
        }

        response_buffer.pos += r;

        int len = decode_ber_length(&response_buffer);
        if (len < 0 || len > sizeof(resp_buf)) {
            syslog(LOG_WARNING, "invalid response length from java sub agent.");
            goto err;
        } else if ((unsigned int) len <= response_buffer.pos) {
            break;
        }
    }

    asn1raw_t tlv;
    response_buffer.pos = 0;
    CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
            "response sequence parse exception");
    CHECK_JAVA_RESPONSE(tlv.type != TAG_SEQUENCE, "wrong response tag");
    init_ibuf(&response_buffer, tlv.value, tlv.length);

    /* skip version, flags, response id */
    CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
            "response version parse exception");
    CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
            "response flags parse exception");
    CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
            "response response ID parse exception");

    /* return code */
    CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
            "result code parse exception");
    CHECK_JAVA_RESPONSE(tlv.type != TAG_ENUMERATED, "wrong result code tag");
    asn1int_t response_code = decode_INTEGER(&tlv);
    if (response_code != 0) {
        syslog(LOG_DEBUG, "java sub agent responded with error code %u.",
                (uint32_t) response_code);
        goto result;
    }

    /* arguments */
    if (type == SUB_AGENT_GET || type == SUB_AGENT_GET_NEXT) {
        asn1raw_t tlv;
        CHECK_JAVA_RESPONSE(decode_TLV(&tlv, &response_buffer),
                "response arguments parse exception");
        CHECK_JAVA_RESPONSE(decode_variable_binding(&tlv, binding),
                "invalid variable binding");
        if (binding->type == SMI_TYPE_OCTET_STRING || binding->type == SMI_TYPE_OPAQUE) {
            uint8_t *val = malloc(binding->value.octet_string.len);
            if (val == NULL) {
                result = GENERAL_ERROR;
            } else {
                memcpy(val, binding->value.octet_string.octets,
                    binding->value.octet_string.len);
                binding->value.octet_string.octets = val;
            }
        }
    }

    goto result;
err:
    syslog(LOG_WARNING, "failed to relay to java sub agent : %s", strerror(errno));
    result = GENERAL_ERROR;

result:
    if (fd != -1) {
        close(fd);
    }
    return result;
}

DEF_METHOD(get_var, SnmpErrorStatus, MibModule, MibModule,
        SnmpVariableBinding *binding)
{
    return send_request(binding, SUB_AGENT_GET, 0);
}

DEF_METHOD(get_next_var, SnmpErrorStatus, MibModule, MibModule,
        SnmpVariableBinding *binding)
{
    return send_request(binding, SUB_AGENT_GET_NEXT, 0);
}

DEF_METHOD(set_var, SnmpErrorStatus, MibModule, MibModule,
        SnmpVariableBinding *binding, int dry_run)
{
    return send_request(binding, SUB_AGENT_SET, dry_run);
}

DEF_METHOD(finish_module, void, MibModule, MibModule)
{
    free(this);
}

MibModule *init_java_subagent_module(void)
{
    MibModule *module = malloc(sizeof(MibModule));
    if (module == NULL) {
        return NULL;
    }

    SET_PREFIX(module, JAVA_MODULE_MIB_OID);
    SET_OR_ENTRY(module, &java_sub_agent_or_entry);
    SET_METHOD(module, MibModule, get_var);
    SET_METHOD(module, MibModule, get_next_var);
    SET_METHOD(module, MibModule, set_var);
    SET_METHOD(module, MibModule, finish_module);
    return module;
}
