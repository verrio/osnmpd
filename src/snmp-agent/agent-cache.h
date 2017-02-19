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

#ifndef SRC_SNMP_AGENT_AGENT_CACHE_H_
#define SRC_SNMP_AGENT_AGENT_CACHE_H_

#include <stdint.h>

/* counters related to the agent request/trap handling */
typedef struct {

	/* amount of incoming SNMP packets. */
	uint32_t snmp_in_pkts;

	/* amount of outgoing SNMP packets. */
	uint32_t snmp_out_pkts;

	/* amount of incoming packets invalid version */
	uint32_t snmp_in_bad_versions;

	/* amount of incoming packets with bad community names */
	uint32_t snmp_in_bad_community_names;

	/* amount of incoming packets with invalid use */
	uint32_t snmp_in_bad_community_uses;

	/* amount of ASN.1 parse errors on incoming messages */
	uint32_t snmp_in_asn_parse_errs;

	/* amount of incoming packets which have a too-big error status */
	uint32_t snmp_in_too_big;

	/* amount of incoming packets which have a no-such-name error status */
	uint32_t snmp_in_no_such_names;

	/* amount of incoming packets which have a bad-value error status */
	uint32_t snmp_in_bad_values;

	/* amount of incoming packets which have a read-only error status */
	uint32_t snmp_in_read_only;

	/* amount of incoming packets which have a genErr error status */
	uint32_t snmp_in_gen_errs;

	/* total amount of returned variables */
	uint32_t snmp_in_total_req_vars;

	/* total amount of changed variables */
	uint32_t snmp_in_total_set_vars;

	/* total amount of incoming get requests */
	uint32_t snmp_in_get_requests;

	/* total amount of incoming get-next requests */
	uint32_t snmp_in_get_nexts;

	/* total amount of incoming set requests */
	uint32_t snmp_in_set_requests;

	/* total amount of incoming get responses */
	uint32_t snmp_in_get_responses;

	/* total amount of incoming traps */
	uint32_t snmp_in_traps;

	/* total amount of outgoing PDUs with a tooBig error status */
	uint32_t snmp_out_too_big;

	/* total amount of outgoing PDUs with a noSuchNames error status */
	uint32_t snmp_out_no_such_names;

	/* total amount of outgoing PDUs with a badValue error status */
	uint32_t snmp_out_bad_values;

	/* total amount of outgoing PDUs with a genErr error status */
	uint32_t snmp_out_gen_errs;

	/* total amount of outgoing get requests */
	uint32_t snmp_out_get_requests;

	/* total amount of outgoing get next requests */
	uint32_t snmp_out_get_nexts;

	/* total amount of outgoing set requests */
	uint32_t snmp_out_set_requests;

	/* total amount of outgoing get responses */
	uint32_t snmp_out_get_responses;

	/* total amount of outgoing traps */
	uint32_t snmp_out_traps;

	/* amount of silently dropped requests */
	uint32_t snmp_silent_drops;

	/* amount of incoming requests for unknown engine */
	uint32_t usm_stats_unknown_engine_ids;

	/* amount of incoming requests for unknown user */
	uint32_t usm_stats_unknown_user_names;

	/* amount of incoming requests with invalid security level */
	uint32_t usm_stats_unsupported_sec_levels;

	/* amount of incoming requests with invalid digest */
	uint32_t usm_stats_wrong_digests;

	/* amount of incoming requests with invalid time window */
	uint32_t usm_stats_not_in_time_windows;

	/* amount of incoming requests with decryption errors */
	uint32_t usm_stats_decryption_errors;

	/* amount of incoming messages with unsupported security model */
	uint32_t snmp_unknown_security_models;

	/* amount of incoming messages with inconsistent components */
	uint32_t snmp_invalid_msgs;

	/* amount of incoming messages without matching engineId and PDU type */
	uint32_t snmp_unknown_pdu_handlers;

	/* time of last outbound communication (seconds) */
	uint32_t last_outbound_timestamp;

	/* amount of failed outbound requests (traps/informs) */
	uint32_t failed_outbound_counter;

} SnmpAgentStatistics;

/**
 * @internal
 * init_cache - initialize the agent cache
 *
 * @return returns 0 on success, -1 on failure.
 */
int init_cache(void);

/**
 * @internal
 * finish_cache - finalize the agent cache
 *
 * @return returns 0 on success, -1 on failure.
 */
int finish_cache(void);

/**
 * @internal
 * get_boot_count - returns the SNMP boot counter.
 *
 * @return SNMP boot counter.
 */
uint32_t get_boot_count(void);

/**
 * @internal
 * reset_boot_count - reset the boot counter.
 *
 * @return returns 0 on success, -1 on failure.
 */
int reset_boot_count(void);

/**
 * @internal
 * get_start_time - returns the system uptime counter at agent's startup
 *
 * @return agent startup timestamp in seconds (relative)
 */
uint64_t get_start_time(void);

/**
 * @internal
 * get_uptime - returns the uptime of the agent (in seconds)
 *
 * @return agent uptime in seconds
 */
uint32_t get_uptime(void);

/**
 * @internal
 * get_statistics - returns the agent's statistics
 *
 * @return agent statistics
 */
SnmpAgentStatistics *get_statistics(void);

#endif /* SRC_SNMP_AGENT_AGENT_CACHE_H_ */
