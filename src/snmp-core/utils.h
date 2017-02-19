/*
 * This file is part of the osnmpd distribution (https://github.com/verrio/osnmpd).
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

#ifndef SRC_SNMP_CORE_UTILS_H_
#define SRC_SNMP_CORE_UTILS_H_

#define SINGLE_PARAM(...) __VA_ARGS__

#ifndef min
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

/**
 * @internal
 * to_hex - Converts byte array to null-terminated string of hex characters.
 *
 * @param byte_array      IN - pointer to start of byte array
 * @param byte_array_size IN - number of valid bytes left in buffer
 * @param destination     OUT - pointer to start of output buffer
 * @param destination_max IN - maximum size of output buffer
 *
 * @return size of resulting string (including null terminator),
 * or -1 on any error
 */
ssize_t to_hex(const uint8_t *byte_array, const size_t byte_array_size,
        char *destination, const size_t destination_max);

/**
 * @internal
 * from_hex - Converts hex string to sequence of bytes.
 *
 * @param hex_str         IN - pointer to start of hex string
 * @param byte_array      OUT - pointer to start of output buffer
 * @param byte_array_max  IN - maximum size of output buffer
 *
 * @return size of resulting byte array, or -1 on any error
 */
ssize_t from_hex(const char *hex_str, uint8_t *byte_array,
        const size_t byte_array_max);

/**
 * @internal
 * strconcat - Concatenate the given strings.
 *
 * @param s1 IN - pointer to start of first string
 * @param s2 IN - pointer to start of second string
 *
 * @return pointer to newly allocated string, or NULL if failed
 */
char* strconcat(const char *s1, const char *s2);

/**
 * @internal
 * memdup - Duplicate a chunk of memory
 *
 * @param src IN - pointer to start of memory range
 * @param src_len IN - length of memory range
 *
 * @return pointer to newly allocated copy, or NULL if failed
 */
void *memdup(void *src, size_t src_len);

/**
 * @internal
 * is_utf8 - Checks if given byte array contains only UTF-8 encoded characters.
 *
 * @param src IN - pointer to start of byte array
 * @param len IN - length of byte array
 *
 * @return 0 if only UTF-8 characters were found, -1 otherwise.
 */
int is_utf8(const uint8_t *src, const size_t len);

/**
 * @internal
 * read_from_file - Reads the content of given file into memory.
 *
 * @param path IN - pathname of file to be read
 * @param dst OUT - destination buffer;  if pointer to NULL, a new buffer is allocated.
 * @param dst_len IN/OUT - destination buffer length
 *
 * @return 0 on success, -1 on error.
 */
int read_from_file(const char *path, uint8_t **dst, size_t *dst_len);

/**
 * @internal
 * write_to_file - Write buffer to file.
 *
 * @param path IN - pathname of file to be (over)written
 * @param val IN - source buffer
 * @param val_len IN - source buffer length
 *
 * @return 0 on success, -1 on error.
 */
int write_to_file(const char *path, const uint8_t *val, const size_t val_len);

#endif /* SRC_SNMP_CORE_UTILS_H_ */
