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
#include <arpa/inet.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/name.h>
#include <dns/rdata.h>

#include "dnstest.h"

static void
rdata_fromtext(dns_rdata_t *rdata, const char *rdata_txt,
	       dns_rdataclass_t rdclass, dns_rdatatype_t rdtype)
{
	char *rdata_txt_mutable;
	isc_lex_t *lex = NULL;
	dns_rdatacallbacks_t callbacks;
	isc_buffer_t source, target;
	static char buf[8192]; /* should be large enough for our tests */

	DE_CONST(rdata_txt, rdata_txt_mutable);
	dns_rdatacallbacks_init(&callbacks);
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       isc_lex_create(mctx, strlen(rdata_txt), &lex));
	isc_buffer_init(&source, rdata_txt_mutable, strlen(rdata_txt_mutable));
	isc_buffer_add(&source, strlen(rdata_txt_mutable));
	isc_buffer_init(&target, buf, sizeof(buf));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS, isc_lex_openbuffer(lex, &source));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdata_fromtext(rdata, rdclass, rdtype, lex,
					  dns_rootname, 0, mctx, &target,
					  &callbacks));
	isc_lex_destroy(&lex);
}

/* A simple helper to generate dns_name_t from C-string.  Not thread-safe. */
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

ATF_TC(rdata_cksum);
ATF_TC_HEAD(rdata_cksum, tc) {
	atf_tc_set_md_var(tc, "descr", "RDATA checksum");
}
ATF_TC_BODY(rdata_cksum, tc) {
	dns_rdata_t rdata;

	UNUSED(tc);

	ATF_REQUIRE_EQ(ISC_R_SUCCESS, dns_test_begin(NULL, ISC_FALSE));

	dns_rdata_init(&rdata);
	/* checksum: 0xc000 + 0x0201 = 0xc201 (in network byte order) */
	rdata_fromtext(&rdata, "192.0.2.1", dns_rdataclass_in, dns_rdatatype_a);
	ATF_REQUIRE_EQ(htons(0xc201), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_rdata_init(&rdata);
	/* checksum: 0x2001 + 0xdb8 + 0x1 */
	rdata_fromtext(&rdata, "2001:db8::1", dns_rdataclass_in,
		       dns_rdatatype_aaaa);
	ATF_REQUIRE_EQ(htons(0x2dba), dns_rdata_cksum(&rdata, ISC_TRUE));

	/* odd-byte length of data */
	dns_rdata_init(&rdata);
	/* checksum: 0x0261 + 0x6100 (note that 'a' = 0x61) */
	rdata_fromtext(&rdata, "aa", dns_rdataclass_in, dns_rdatatype_txt);
	ATF_REQUIRE_EQ(htons(0x6361), dns_rdata_cksum(&rdata, ISC_TRUE));

	/* overflow case */
	dns_rdata_init(&rdata);
	/* checksum: 0x03ff + 0xffff = 0x103fe (overflow) => 0x3ff */
	rdata_fromtext(&rdata, "\\255\\255\\255", dns_rdataclass_in,
		       dns_rdatatype_txt);
	ATF_REQUIRE_EQ(htons(0x3ff), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_rdata_init(&rdata);
	/*
	 * checksum: 0x07ff + 0xf7fc + 0xffff + 0x0005 = 0x1ffff (overflow)
	 *           => 0x10000 (still overflow) => 0x1
	 */
	rdata_fromtext(&rdata, "\\255\\247\\252\\255\\255\\000\\005",
		       dns_rdataclass_in, dns_rdatatype_txt);
	ATF_REQUIRE_EQ(htons(1), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_test_end();
}

ATF_TC(name_cksum);
ATF_TC_HEAD(name_cksum, tc) {
	atf_tc_set_md_var(tc, "descr", "name checksum");
}
ATF_TC_BODY(name_cksum, tc) {
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
	ATF_TP_ADD_TC(tp, name_cksum);
	ATF_TP_ADD_TC(tp, rdata_cksum);

	return (atf_no_error());
}
