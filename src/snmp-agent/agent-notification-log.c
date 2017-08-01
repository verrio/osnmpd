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
#include <fcntl.h>
#include <inttypes.h>
#include <mqueue.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-notification-log.h"
#include "snmp-agent/agent-notification-builder.h"
#include "snmp-core/snmp-pdu.h"
#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

/**
 * The notification log consists of fixed header followed by multiple compressed
 * chunks of 4K, containing up to 0x500 events each.  Each chunk contains
 * a variable binding mask for easier traversal.  New entries are appended
 * in circular (FIFO) fashion.
 *
 * log header format:
 * +-------+---------+-----------+------------------+-------------+
 * | magic | version | engine id | number of chunks | header size |
 * +-------+---------+-----------+------------------+-------------+
 * +-------------------------+-------------------------+----------+
 * | chunk index of log head | chunk index of log tail | checksum |
 * +-------------------------+-------------------------+----------+
 * +---------+---------...---------+
 * | padding | optional debug info |
 * +---------+---------...---------+
 *
 * chunk format:
 * +-----------+----------+------------------+-----...-----+
 * | entry cnt | var mask | len (compressed) |   entries   |
 * +-----------+----------+------------------+-----...-----+
 *
 * the entries are deflated before storing to flash
 *
 * chunk entry format:
 * +----------+--------------+-----------+---------+-------...-----+-----+
 * | var mask | agent uptime | timestamp | var cnt | var bindings  | len |
 * +----------+--------------+-----------+---------+-------...-----+-----+
 *
 * length tag at the end for reverse traversal.
 */

#define LOG_FILE       "trap.log"
#define LOG_MAGIC      "OSNMP-TRAP-LOG"
#define LOG_VERSION    0x01
#define HEADER_SIZE    256
#define HEAD_TOP       76
#define MIN_LOG_SIZE   32768
#define MAX_LOG_SIZE   20971520
#define CHUNK_SIZE     4096
#define MAX_COMPRESS   4
#define ZLIB_CMF       0x68
#define ZLIB_FLG       0x81
#define ZLIB_LEVEL     6
#define ZLIB_WINDOW    14
#define CHUNK_FULL     -2

#define READ_UINT16(buf, offset) \
        (((0xff & buf[offset]) << 8) | (0xff & buf[offset + 1]))
#define WRITE_UINT16(buf, offset, val) do { \
        buf[offset] = 0xff & (val >> 8); \
        buf[offset + 1] = 0xff & val; \
    } while (0);
#define READ_UINT32(buf, offset) \
        (((0xff & buf[offset]) << 24) | ((0xff & buf[offset + 1]) << 16) | \
        ((0xff & buf[offset + 2]) << 8) | (0xff & buf[offset + 3]))
#define READ_UINT64(buf, offset) \
        (((0xffLL & buf[offset]) << 56) | ((0xffLL & buf[offset + 1]) << 48) | \
        ((0xffLL & buf[offset + 2]) << 40) | ((0xffLL & buf[offset + 3]) << 32) | \
        ((0xffLL & buf[offset + 4]) << 24) | ((0xffLL & buf[offset + 5]) << 16) | \
        ((0xffLL & buf[offset + 6]) << 8) | (0xffLL & buf[offset + 7]))
#define WRITE_UINT32(buf, offset, val) do { \
        buf[offset] = 0xff & (val >> 24); \
        buf[offset + 1] = 0xff & (val >> 16); \
        buf[offset + 2] = 0xff & (val >> 8); \
        buf[offset + 3] = 0xff & val; \
    } while (0);
#define WRITE_UINT64(buf, offset, val) do { \
        buf[offset] = 0xff & (val >> 56); \
        buf[offset + 1] = 0xff & (val >> 48); \
        buf[offset + 2] = 0xff & (val >> 40); \
        buf[offset + 3] = 0xff & (val >> 32); \
        buf[offset + 4] = 0xff & (val >> 24); \
        buf[offset + 5] = 0xff & (val >> 16); \
        buf[offset + 6] = 0xff & (val >> 8); \
        buf[offset + 7] = 0xff & val; \
    } while (0);

#define FILTER_SMI_TYPE_OCTET_STRING    0x0001
#define FILTER_SMI_TYPE_OID             0x0002
#define FILTER_SMI_TYPE_INTEGER_32      0x0004
#define FILTER_SMI_TYPE_IP_ADDRESS      0x0008
#define FILTER_SMI_TYPE_COUNTER_32      0x0010
#define FILTER_SMI_TYPE_GAUGE_32        0x0020
#define FILTER_SMI_TYPE_TIME_TICKS      0x0040
#define FILTER_SMI_TYPE_OPAQUE          0x0080
#define FILTER_SMI_TYPE_COUNTER_64      0x0100
#define FILTER_SMI_TYPE_NULL            0x0200

typedef struct {
    uint32_t discarded;
    uint32_t num_of_chunks;
    uint16_t chunk_head;
    uint16_t chunk_tail;
    int16_t *chunks;
    uint16_t *chunk_vars;
    int16_t cur_chunk;
    size_t chunk_len;
    uint8_t chunk_buf[CHUNK_SIZE << 5];
    int log_file;
} TrapLog;

static TrapLog trap_log;

static int trap_log_open(TrapLog *);
static int read_header(TrapLog *);
static int write_header(TrapLog *, int);
static uint16_t get_chunk_entries(TrapLog *, uint16_t);
static int chunk_var_match(TrapLog *, uint16_t, SMIType);
static int write_cur_chunk(TrapLog *);
static int load_cur_chunk(TrapLog *, uint16_t);
static int read_entry(TrapLog *, uint16_t, uint16_t, uint16_t, LoggedTrapEntry *);
static int append_trap(TrapLog *, const SnmpScopedPDU *const);
static uint16_t get_var_filter(SMIType);

int init_trap_log(void)
{
    uint32_t log_size = get_max_log_size();
    if (log_size < MIN_LOG_SIZE) {
        syslog(LOG_WARNING, "notification log disabled");
        log_size = 0;
    } else if (log_size > MAX_LOG_SIZE) {
        syslog(LOG_WARNING, "log size %"PRIu32" too large", log_size);
        log_size = MAX_LOG_SIZE;
    }

    trap_log.discarded = 0;
    trap_log.num_of_chunks = log_size == 0 ? 0 : (log_size - HEADER_SIZE) / CHUNK_SIZE;
    trap_log.chunk_head = 0;
    trap_log.chunk_tail = 0;
    trap_log.log_file = -1;
    trap_log.cur_chunk = -1;
    trap_log.chunk_len = 0;

    if (trap_log.num_of_chunks == 0) {
        trap_log.chunk_vars = NULL;
        trap_log.chunks = NULL;
        return 0;
    } else {
        trap_log.chunk_vars = calloc(trap_log.num_of_chunks, sizeof(uint16_t));
        trap_log.chunks = calloc(trap_log.num_of_chunks, sizeof(int16_t));
        if (trap_log.chunks == NULL || trap_log.chunk_vars == NULL)
            return -1;
        memset(trap_log.chunks, 0xff, trap_log.num_of_chunks * sizeof(uint16_t));
        return trap_log_open(&trap_log);
    }
}

int finish_trap_log(void)
{
    if (trap_log.log_file != -1) {
        fsync(trap_log.log_file);
        close(trap_log.log_file);
    }
    trap_log.log_file = -1;
    free(trap_log.chunks);
    free(trap_log.chunk_vars);
    return 0;
}

int store_new_log_entry(const SnmpScopedPDU *const scoped_pdu)
{
    if (trap_log.num_of_chunks == 0) {
        syslog(LOG_DEBUG, "notification log disabled.");
        return 0;
    }
    if (load_cur_chunk(&trap_log, trap_log.chunk_head))
        return -1;
    int16_t tmp_entries = trap_log.chunks[trap_log.cur_chunk];
    uint16_t tmp_vars = trap_log.chunk_vars[trap_log.cur_chunk];

    int ret = append_trap(&trap_log, scoped_pdu);
    if (ret == CHUNK_FULL)
        goto next_chunk;
    if (ret < 0)
        return -1;
    ret = write_cur_chunk(&trap_log);
    if (ret == CHUNK_FULL)
        goto next_chunk;
    return ret;
next_chunk:
    trap_log.chunks[trap_log.cur_chunk] = tmp_entries;
    trap_log.chunk_vars[trap_log.cur_chunk] = tmp_vars;

    trap_log.cur_chunk = (trap_log.cur_chunk + 1) % trap_log.num_of_chunks;
    trap_log.chunk_head = trap_log.cur_chunk;
    if (trap_log.cur_chunk == trap_log.chunk_tail) {
        trap_log.discarded += get_chunk_entries(&trap_log, trap_log.cur_chunk);
        trap_log.chunk_tail = (trap_log.cur_chunk + 1) % trap_log.num_of_chunks;
    }

    trap_log.chunk_len = 0;
    trap_log.chunks[trap_log.cur_chunk] = 0;
    trap_log.chunk_vars[trap_log.cur_chunk] = 0;
    if (write_header(&trap_log, 0))
        return -1;
    if (append_trap(&trap_log, scoped_pdu) < 0)
        return -1;
    return write_cur_chunk(&trap_log) != 0;
}

int get_trap_entry(uint32_t index, SMIType var_filter, LoggedTrapEntry *dst)
{
    if (trap_log.num_of_chunks == 0) {
        syslog(LOG_DEBUG, "notification log disabled.");
        return -1;
    }

    if (index) index--;
    uint32_t acc = 0;
    uint16_t chunk = trap_log.chunk_head;

    while (1) {
        while (1) {
            if (acc + get_chunk_entries(&trap_log, chunk) > index &&
                chunk_var_match(&trap_log, chunk, var_filter)) {
                break;
            }

            if (chunk == trap_log.chunk_tail)
                return -1;
            acc += get_chunk_entries(&trap_log, chunk);
            chunk = chunk == 0 ? trap_log.num_of_chunks - 1 : chunk -1;
        }

        if (read_entry(&trap_log, chunk, index - acc,
            var_filter == 0 ? UINT16_MAX : get_var_filter(var_filter), dst)) {
            if (chunk == trap_log.chunk_tail)
                return -1;
            acc += get_chunk_entries(&trap_log, chunk);
            chunk = chunk == 0 ? trap_log.num_of_chunks - 1 : chunk - 1;
        } else {
            dst->index += acc + 1;
            return 0;
        }
    }
}

uint32_t get_num_log_entries(void)
{
    if (trap_log.log_file == -1)
        return 0;

    uint32_t acc = 0;
    uint16_t chunk = trap_log.chunk_tail;
    while (1) {
        acc += get_chunk_entries(&trap_log, chunk);
        if (chunk == trap_log.chunk_head)
            break;
        chunk = (chunk + 1) % trap_log.num_of_chunks;
    };

    return acc;
}

uint32_t get_max_log_entries(void)
{
    if (trap_log.log_file == -1)
        return 0;
    return trap_log.num_of_chunks * MAX_COMPRESS * CHUNK_SIZE / 128;
}

uint32_t get_num_log_discarded(void)
{
    return trap_log.discarded;
}

static int trap_log_open(TrapLog *log)
{
    char *log_file = strconcat(get_cache_dir(), LOG_FILE);
    if (log_file == NULL)
        return -1;

    log->log_file = open(log_file, O_RDWR | O_CREAT, 0664);
    free(log_file);
    if (log->log_file == -1) {
        syslog(LOG_ERR, "failed to open trap log : %s", strerror(errno));
        return -1;
    }
    if (get_agent_uid() != -1 && get_agent_gid() != -1 &&
        fchown(log->log_file, get_agent_uid(), get_agent_gid())) {
        syslog(LOG_WARNING, "failed to set trap log owner : %s", strerror(errno));
    }

    off_t size = lseek(log->log_file, 0, SEEK_END);
    if (size < 0) {
        syslog(LOG_WARNING, "failed to determine trap log size : %s", strerror(errno));
        return -1;
    }

    int new_header = 0;
    if (size == 0) {
        syslog(LOG_INFO, "initialising new trap log");
        if (ftruncate(log->log_file, HEADER_SIZE + trap_log.num_of_chunks * CHUNK_SIZE) != 0) {
            syslog(LOG_ERR, "failed to initialise trap log : %s", strerror(errno));
            return -1;
        }

        new_header = 1;
        uint8_t tmp[4];
        memset(tmp, 0, sizeof(tmp));
        if (pwrite(log->log_file, tmp, sizeof(tmp), HEADER_SIZE) < 0) {
            syslog(LOG_ERR, "failed to clear trap log : %s", strerror(errno));
            return -1;
        }
    } else if (size != HEADER_SIZE + trap_log.num_of_chunks * CHUNK_SIZE) {
        syslog(LOG_WARNING, "trap log has invalid file size");
        if (ftruncate(log->log_file, HEADER_SIZE + trap_log.num_of_chunks * CHUNK_SIZE) != 0) {
            syslog(LOG_ERR, "failed to resize trap log : %s", strerror(errno));
            return -1;
        }
        new_header = 1;
    }

    if (size > HEADER_SIZE && read_header(log)) {
        syslog(LOG_WARNING, "failed to parse header : %s", strerror(errno));
        return -1;
    }

    return new_header ? write_header(log, 1) : 0;
}

static int read_header(TrapLog *log)
{
    uint8_t head_buf[HEADER_SIZE >> 1];
    if (pread(log->log_file, head_buf, sizeof(head_buf), 0) != HEADER_SIZE >> 1) {
        syslog(LOG_WARNING, "failed to read log header : %s", strerror(errno));
        return -1;
    }

    uint32_t checksum = adler32(0L, Z_NULL, 0);
    checksum = adler32(checksum, head_buf, HEAD_TOP);
    uint32_t orig_checksum = READ_UINT32(head_buf, HEAD_TOP);
    if (orig_checksum != checksum) {
        syslog(LOG_WARNING, "checksum in log header does not match");
    }

    int offset = 0;
    if (memcmp(LOG_MAGIC, head_buf, strlen(LOG_MAGIC))) {
        syslog(LOG_WARNING, "log file has unknown format");
        return -1;
    }
    offset += 30;

    int version = READ_UINT16(head_buf, offset);
    if (version != LOG_VERSION) {
        syslog(LOG_WARNING, "log file has unsupported version");
        return -1;
    }
    offset += 2;

    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    uint8_t engine_id_padded[ENGINE_ID_MAX_LEN];
    memcpy(engine_id_padded, engine_id, engine_id_len);
    memset(&engine_id_padded[engine_id_len], 0, ENGINE_ID_MAX_LEN - engine_id_len);
    if (memcmp(engine_id, engine_id_padded, ENGINE_ID_MAX_LEN)) {
        syslog(LOG_WARNING, "log file of different device detected");
    }
    offset += ENGINE_ID_MAX_LEN;

    uint32_t chunks = READ_UINT16(head_buf, offset);
    if (chunks != log->num_of_chunks) {
        syslog(LOG_WARNING, "log file header indicates wrong amount of chunks");
    }
    offset += 2;

    uint32_t chunk_start = READ_UINT16(head_buf, offset);
    if (chunk_start != HEADER_SIZE) {
        syslog(LOG_WARNING, "log file header indicates wrong chunk offset");
    }
    offset += 2;

    uint32_t log_head = READ_UINT16(head_buf, offset);
    uint32_t log_tail = READ_UINT16(head_buf, offset + 2);
    offset += 4;

    if (log_head >= log->num_of_chunks) {
        syslog(LOG_WARNING, "log file header indicates invalid log head");
    } else if (chunks >= log->num_of_chunks) {
        log->chunk_head = log_head;
    }
    if (log_tail >= log->num_of_chunks) {
        syslog(LOG_WARNING, "log file header indicates invalid log tail");
    } else if (chunks >= log->num_of_chunks) {
        log->chunk_tail = log_tail;
    }

    return 0;
}

static int write_header(TrapLog *log, int meta_data)
{
    uint8_t head_buf[HEADER_SIZE];
    memset(head_buf, 0, HEAD_TOP);

    /* magic + version */
    strcpy((char *) head_buf, LOG_MAGIC);
    WRITE_UINT16(head_buf, 30, LOG_VERSION);

    /* engine id */
    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    memcpy(&head_buf[32], engine_id, engine_id_len);

    /* counters */
    WRITE_UINT16(head_buf, 64, log->num_of_chunks);
    WRITE_UINT16(head_buf, 66, HEADER_SIZE);
    WRITE_UINT16(head_buf, 68, log->chunk_head);
    WRITE_UINT16(head_buf, 70, log->chunk_tail);

    /* checksum */
    uint32_t checksum = adler32(0L, Z_NULL, 0);
    checksum = adler32(checksum, head_buf, HEAD_TOP);
    WRITE_UINT32(head_buf, HEAD_TOP, checksum);
    for (int i = HEAD_TOP + 4; i < (HEADER_SIZE >> 1); i++)
        head_buf[i] = i & 0x01 ? 0x55 : 0xAA;

    /* debug info */
    if (meta_data) {
        time_t current_time = time(NULL);
        memset(&head_buf[HEADER_SIZE >> 1], 0, HEADER_SIZE >> 1);
        int offset = HEADER_SIZE >> 1;
        size_t buf_left = HEADER_SIZE >> 1;
        int written = snprintf((char *) &head_buf[offset],
            buf_left, "AGENT=%s", PACKAGE_STRING) + 1;
        if (written < buf_left) {
            buf_left -= written;
            offset += written;
            written = snprintf((char *) &head_buf[offset],
                buf_left, "ZLIB=%s", zlibVersion()) + 1;
        }
        if (written < buf_left) {
            buf_left -= written;
            offset += written;
            snprintf((char *) &head_buf[offset],
                buf_left, "DATE=%s", ctime(&current_time));
        }
    }

    if (log->log_file == -1)
        return -1;

    int offset = 0;
    int rem = meta_data ? HEADER_SIZE : (HEADER_SIZE >> 1);
    while (rem > 0) {
        ssize_t written = pwrite(log->log_file, &head_buf[offset], rem, 0);
        if (written <= 0)
            return -1;
        rem -= written;
        offset += written;
    }
    return 0;
}

static int write_cur_chunk(TrapLog *log)
{
    int ret = 0;
    if (log->cur_chunk == -1 || log->log_file == -1)
        return -1;

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit2(&strm, ZLIB_LEVEL, Z_DEFLATED,
        ZLIB_WINDOW, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    strm.avail_in = log->chunk_len;
    strm.next_in = log->chunk_buf;

    uint8_t out_buf[CHUNK_SIZE];
    strm.avail_out = CHUNK_SIZE - 6;
    strm.next_out = out_buf + 6;
    ret = deflate(&strm, Z_FINISH);

    if (ret == Z_STREAM_END) {
        WRITE_UINT16(out_buf, 0, log->chunks[log->cur_chunk]);
        WRITE_UINT16(out_buf, 2, log->chunk_vars[log->cur_chunk]);
        WRITE_UINT16(out_buf, 4, strm.total_out);

        int offset = 0;
        int rem = strm.total_out + 6;
        while (rem > 0) {
            ssize_t written = pwrite(log->log_file, &out_buf[offset], rem,
                    HEADER_SIZE + CHUNK_SIZE * log->cur_chunk + offset);
            if (written <= 0) {
                ret = -1;
                break;
            }
            rem -= written;
            offset += written;
        }
        ret = 0;
    } else if ((ret == Z_OK || ret == Z_BUF_ERROR) && strm.avail_out == 0) {
        ret = CHUNK_FULL;
    } else {
        syslog(LOG_ERR, "failed to compress notification log block : return code %i\n", ret);
        ret = -1;
    }

    deflateEnd(&strm);
    return ret;
}

static int load_cur_chunk(TrapLog *log, uint16_t chunk)
{
    int ret = 0;
    if (log->log_file == -1)
        return -1;
    if (log->cur_chunk == chunk)
        return 0;
    log->cur_chunk = -1;
    log->chunk_len = 0;

    int offset = 0;
    int rem = CHUNK_SIZE;
    uint8_t in_buf[CHUNK_SIZE];
    while (rem > 0) {
        ssize_t read = pread(log->log_file, &in_buf[offset], rem,
            HEADER_SIZE + chunk * CHUNK_SIZE + offset);
        if (read <= 0)
            return -1;
        offset += read;
        rem -= read;
    }

    log->chunks[chunk] = READ_UINT16(in_buf, 0);
    if (log->chunks[chunk] <= 0)
        goto empty_block;
    log->chunk_vars[chunk] = READ_UINT16(in_buf, 2);
    size_t len = READ_UINT16(in_buf, 4);
    if (len > CHUNK_SIZE - 6) {
        syslog(LOG_WARNING, "log block has invalid length");
        goto empty_block;
    }

    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, ZLIB_WINDOW);
    if (ret != Z_OK)
        return -1;

    strm.avail_in = len;
    strm.next_in = in_buf + 6;
    strm.avail_out = CHUNK_SIZE << 5;
    strm.next_out = log->chunk_buf;

    do {
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            break;
    } while (ret != Z_STREAM_END);
    if (ret != Z_STREAM_END) {
        ret = -1;
    } else {
        log->cur_chunk = chunk;
        log->chunk_len = strm.total_out;
        ret = 0;
    }

    inflateEnd(&strm);
    if (ret == 0)
        return 0;
empty_block:
    log->cur_chunk = chunk;
    log->chunks[chunk] = 0;
    log->chunk_vars[chunk] = 0;
    log->chunk_len = 0;
    return ret;
}

static int read_chunk_header(TrapLog *log, uint16_t chunk)
{
    if (log->log_file == -1)
        return -1;
    uint8_t buf[8];
    if (pread(log->log_file, buf, sizeof(buf), chunk * CHUNK_SIZE + HEADER_SIZE) != 8) {
        syslog(LOG_WARNING, "failed to read chunk header : %s", strerror(errno));
        return -1;
    }
    if ((READ_UINT16(buf, 0) > 0) && (buf[6] != ZLIB_CMF || buf[7] != ZLIB_FLG)) {
        syslog(LOG_WARNING, "log chunk contains invalid compression header %2x:%2x", buf[6], buf[7]);
        return -1;
    }

    log->chunks[chunk] = READ_UINT16(buf, 0);
    log->chunk_vars[chunk] = READ_UINT16(buf, 2);
    return 0;
}

static int read_entry(TrapLog *log, uint16_t chunk, uint16_t min,
        uint16_t var_filter, LoggedTrapEntry *dst)
{
    if (load_cur_chunk(log, chunk))
        return -1;
    if (log->chunks[chunk] <= min)
        return -1;

    size_t offset = log->chunk_len;
    for (int i = log->chunks[chunk] - 1; i >= 0; i--) {
        if (offset < 2)
            return -1;
        offset -= 2;
        size_t size = READ_UINT16(log->chunk_buf, offset);
        if (size > offset)
            return -1;
        offset -= size;
        if (offset + 16 >= log->chunk_len)
            return -1;

        uint16_t vars = READ_UINT16(log->chunk_buf, offset);
        if ((var_filter & vars) == 0 || log->chunks[chunk] - i - 1 < min)
            continue;

        dst->index = log->chunks[chunk] - i - 1;
        dst->uptime = READ_UINT32(log->chunk_buf, offset + 2);
        dst->timestamp = READ_UINT64(log->chunk_buf, offset + 6);
        dst->num_of_vars = log->chunk_buf[offset + 14];

        buf_t ibuf;
        init_ibuf(&ibuf, &log->chunk_buf[offset + 15], log->chunk_len - offset - 15);
        for (int j = 0; j < dst->num_of_vars; j++) {
            asn1raw_t seq;
            if (decode_TLV(&seq, &ibuf) < 0)
                return -1;
            if (decode_variable_binding(&seq, &dst->vars[j]))
                return -1;
        }

        if (dst->num_of_vars > 1 && dst->vars[1].type == SMI_TYPE_OID) {
            COPY_OID(&dst->trap_type, &dst->vars[1].value.oid);
        } else {
            SET_OID(dst->trap_type, 0, 0);
        }

        return 0;
    }

    return -1;
}

static uint16_t get_chunk_entries(TrapLog *log, uint16_t chunk)
{
    if (log->chunks[chunk] == -1 && read_chunk_header(log, chunk))
        return 0;

    return log->chunks[chunk];
}

static int chunk_var_match(TrapLog *log, uint16_t chunk, SMIType type)
{
    if (type == 0)
        return 1;
    if (log->chunk_vars[chunk] == 0xffff && read_chunk_header(log, chunk))
        return 0;
    return log->chunk_vars[chunk] & get_var_filter(type);
}

static int append_trap(TrapLog *log, const SnmpScopedPDU *const scoped_pdu)
{
    if (log->cur_chunk == -1)
        return -1;
    if (log->chunks[log->cur_chunk] >= 0x500)
        return CHUNK_FULL;

    uint16_t var_mask = 0;
    buf_t out_buf;
    init_obuf(&out_buf, &log->chunk_buf[log->chunk_len],
        sizeof(log->chunk_buf) - log->chunk_len);

    if (out_buf.size < 2)
        return -1;
    out_buf.pos -= 2;
    uint8_t *len_ptr = &out_buf.buffer[out_buf.pos];

    for (int i = scoped_pdu->num_of_bindings - 1; i >= 0; i--) {
        const SnmpVariableBinding * const binding = &scoped_pdu->bindings[i];
        var_mask |= get_var_filter(binding->type);
        if (encode_variable_binding(binding, &out_buf))
            return CHUNK_FULL;
    }

    if (out_buf.pos < 16)
        return CHUNK_FULL;
    out_buf.buffer[--out_buf.pos] = scoped_pdu->num_of_bindings;

    struct timespec system_time;
    if (clock_gettime(CLOCK_REALTIME, &system_time) == -1)
        return -1;
    uint64_t timestamp = ((uint64_t) system_time.tv_sec) * 1000 +
            ((uint64_t) system_time.tv_nsec) / 1000000;
    out_buf.pos -= 8;
    WRITE_UINT64(out_buf.buffer, out_buf.pos, timestamp);

    out_buf.pos -= 4;
    uint32_t uptime = get_uptime();
    WRITE_UINT32(out_buf.buffer, out_buf.pos, uptime);

    out_buf.pos -= 2;
    WRITE_UINT16(out_buf.buffer, out_buf.pos, var_mask);

    uint16_t len = out_buf.size - out_buf.pos;
    WRITE_UINT16(len_ptr, 0, (len - 2));

    memmove(out_buf.buffer, &out_buf.buffer[out_buf.pos], len);
    log->chunk_len += len;
    log->chunk_vars[log->cur_chunk] |= var_mask;
    log->chunks[log->cur_chunk]++;
    return 0;
}

static uint16_t get_var_filter(SMIType type)
{
    switch (type) {
        case SMI_TYPE_OCTET_STRING:
            return FILTER_SMI_TYPE_OCTET_STRING;
        case SMI_TYPE_NULL:
            return FILTER_SMI_TYPE_NULL;
        case SMI_TYPE_OID:
            return FILTER_SMI_TYPE_OID;
        case SMI_TYPE_INTEGER_32:
            return FILTER_SMI_TYPE_INTEGER_32;
        case SMI_TYPE_IP_ADDRESS:
            return FILTER_SMI_TYPE_IP_ADDRESS;
        case SMI_TYPE_COUNTER_32:
            return FILTER_SMI_TYPE_COUNTER_32;
        case SMI_TYPE_GAUGE_32:
            return FILTER_SMI_TYPE_GAUGE_32;
        case SMI_TYPE_TIME_TICKS:
            return FILTER_SMI_TYPE_TIME_TICKS;
        case SMI_TYPE_OPAQUE:
            return FILTER_SMI_TYPE_OPAQUE;
        case SMI_TYPE_COUNTER_64:
            return FILTER_SMI_TYPE_COUNTER_64;
        default:
            return 0;
    }
}
