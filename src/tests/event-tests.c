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
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <mqueue.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "snmp-core/tinyber.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/agent-notification-builder.h"

#define MAX_MESSAGE_SIZE    512
#define NOTIFICATION_TX_QUEUE   "/snmp-notifications"

#define CHECK_RESULT(x) do { \
    int retval = (x); \
    if (retval != 0) { \
        return -1; \
    } \
} while (0)

typedef struct {
    uint8_t version;
    uint8_t flags;
    uint64_t timestamp;
    uint16_t trap_code_1;
    uint16_t trap_code_2;
    uint8_t *arguments;
    size_t arguments_len;
} test_event;

int event_marshall(test_event *event, uint8_t *buffer,
        size_t buf_len, uint8_t **result, size_t *result_len);

int main(int ac, char **av)
{
    int print_result = 0;
    int opt;
    while ((opt = getopt(ac, av, "d?")) != -1) {
        switch (opt) {
            case 'd': {
                print_result = 1;
                break;
            }

            case '?':
            default: {
                fprintf(stderr, "usage: event-tests <trap-code-1> <trap-code-2> <message>*\n");
                exit(0);
            }
        }
    }

    int argind = optind;

    if (ac - argind > 3 || ac - argind < 2)
        exit(1);

    test_event event;

    errno = 0;
    event.trap_code_1 = (uint16_t) strtol(av[argind++], NULL, 0);
    if (errno != 0) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }
    event.trap_code_2 = (uint16_t) strtol(av[argind++], NULL, 0);
    if (errno != 0) {
        perror("strtol");
        exit(EXIT_FAILURE);
    }

    if (argind < ac) {
        uint8_t buf[MAX_MESSAGE_SIZE - 0x40];
        buf_t string_buf;
        init_obuf(&string_buf, buf, sizeof(buf));
        if (encode_OCTET_STRING(&string_buf, (uint8_t *) av[argind], strlen(av[argind])) == -1) {
            fprintf(stderr, "message exceeds maximum of %d characters", MAX_MESSAGE_SIZE - 0x40);
            exit(EXIT_FAILURE);
        }
        event.arguments = string_buf.buffer + string_buf.pos;
        event.arguments_len = (string_buf.size - string_buf.pos);
    } else {
        event.arguments_len = 0;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    event.timestamp = (ts.tv_sec * ((int64_t) 1000)) + (ts.tv_nsec / ((int64_t) 1000000));
    event.version = NOTIFICATION_VERSION;
    event.flags = 0x00;

    uint8_t buf[MAX_MESSAGE_SIZE - 0x40];
    uint8_t *buf_start;
    size_t buf_len;
    if (event_marshall(&event, buf, sizeof(buf), &buf_start, &buf_len) == -1) {
        fprintf(stderr, "failed to marshall event.\n");
        exit(EXIT_FAILURE);
    }

    struct mq_attr event_queue_attr;
    event_queue_attr.mq_flags = 0;
    event_queue_attr.mq_maxmsg = 64;
    event_queue_attr.mq_msgsize = MAX_MESSAGE_SIZE;
    event_queue_attr.mq_curmsgs = 0;

    mqd_t event_queue = mq_open(NOTIFICATION_TX_QUEUE,
            O_CREAT | O_WRONLY | O_NONBLOCK, 0666, &event_queue_attr);
    if (event_queue == (mqd_t)-1) {
        fprintf(stderr, "Failed to open message queue: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (print_result) {
        printf("sending event on %s\n", NOTIFICATION_TX_QUEUE);
    }

    int ok;
    if (mq_send(event_queue, (char *) buf_start, buf_len, 0) == -1) {
        fprintf(stderr, "failed to dispatch event : %s\n", strerror(errno));
        ok = 0;
    } else {
        ok = 1;
    }

    mq_close(event_queue);
    if (ok) {
        if (print_result) {
            fprintf(stderr, "dispatched successfully\n");
        }
        exit(EXIT_SUCCESS);
    } else {
        exit(EXIT_FAILURE);
    }
}

int event_marshall(test_event *event, uint8_t *buffer, size_t buf_len,
        uint8_t **result, size_t *result_len)
{
    buf_t buf;
    asn1int_t int_buf;
    init_obuf(&buf, buffer, buf_len);

    /* arguments */
    CHECK_RESULT(event->arguments_len > buf_len);
    buf.pos -= event->arguments_len;
    memcpy(buf.buffer + buf.pos, event->arguments, event->arguments_len);
    CHECK_RESULT(encode_TLV(&buf, buf.size, TAG_SEQUENCE, FLAG_STRUCTURED));

    /* trap codes */
    int_buf = event->trap_code_2;
    CHECK_RESULT(encode_INTEGER(&buf, &int_buf, TAG_INTEGER, FLAG_UNIVERSAL));
    int_buf = event->trap_code_1;
    CHECK_RESULT(encode_INTEGER(&buf, &int_buf, TAG_INTEGER, FLAG_UNIVERSAL));

    /* timestamp */
    CHECK_RESULT(encode_INTEGER(&buf, (int64_t *) &event->timestamp, TAG_INTEGER, FLAG_UNIVERSAL));

    /* flags */
    CHECK_RESULT(encode_BITSTRING(&buf, &event->flags));

    /* version */
    int_buf = event->version;
    CHECK_RESULT(encode_INTEGER(&buf, &int_buf, TAG_INTEGER, FLAG_UNIVERSAL));

    /* sequence */
    CHECK_RESULT(encode_TLV(&buf, buf.size, TAG_SEQUENCE, FLAG_STRUCTURED));

    if (result != NULL) *result = buf.buffer + buf.pos;
    if (result_len != NULL) *result_len = buf.size - buf.pos;
    return 0;
}
