/*
 * Copyright (C) 2014  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

/*! \file */

#include <config.h>

#include <atf-c.h>

#include <unistd.h>

#include <dns/name.h>

#include "dnstest.h"

static dns_name_t *
name_fromtext(const char *name_txt) {
	static dns_fixedname_t fn;
	dns_name_t *name;
	isc_buffer_t buf;

	isc_buffer_constinit(&buf, name_txt, strlen(name_txt));
	isc_buffer_add(&buf, strlen(name_txt));

	dns_fixedname_init(&fn);
	name = dns_fixedname_name(&fn);
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_name_fromtext(name, &buf, dns_rootname, 0, NULL));
	return (name);
}

ATF_TC(cksum);
ATF_TC_HEAD(cksum, tc) {
	atf_tc_set_md_var(tc, "descr", "name checksum");
}
ATF_TC_BODY(cksum, tc) {
	const char *long_name;

	/*
	 * A simple case: the cheksum for the root name (consisting of a single
	 * null byte) should be 0.
	 */
	ATF_REQUIRE_EQ(0, dns_name_cksum(dns_rootname, ISC_FALSE));
	ATF_REQUIRE_EQ(0, dns_name_cksum(dns_rootname, ISC_TRUE));

	/*
	 * 'a' = 97, so the checksum for "aaa." is 3(=# 1st labels) + 97 * 3.
	 * Similar to "AAA." ('A' = 65)
	 */
	ATF_REQUIRE_EQ(3 + 97 * 3,
		       dns_name_cksum(name_fromtext("aaa."), ISC_TRUE));
	ATF_REQUIRE_EQ(3 + 65 * 3,
		       dns_name_cksum(name_fromtext("AAA."), ISC_TRUE));

	/*
	 * If it's case insensitive, both should be equal to the checksum of
	 * 'aaa.'
	 */
	ATF_REQUIRE_EQ(3 + 97 * 3,
		       dns_name_cksum(name_fromtext("aaa."), ISC_FALSE));
	ATF_REQUIRE_EQ(3 + 97 * 3,
		       dns_name_cksum(name_fromtext("AAA."), ISC_FALSE));

	/*
	 * A very long name, one possibly provides a largest checksum:
	 * 1st-3rd label: 63 + 63 0xff's
	 * 4th label: 61 + 61 0xff's
	 * then terminating '.'
	 * So the checksum should be:
	 * (63 + 255 * 63) * 3 + 61 + 255 * 61 = 64000
	 */
	long_name =
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255" /* up to 64 bytes */
		".\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255" /* up to 128 bytes */
		".\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255" /* up to 192 bytes */
		".\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255\\255\\255\\255"
		"\\255\\255\\255\\255\\255."; /* up to 255 bytes */
	ATF_REQUIRE_EQ(64000,
		       dns_name_cksum(name_fromtext(long_name), ISC_FALSE));
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, cksum);

	return (atf_no_error());
}
