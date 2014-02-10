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
#include <isc/net.h>
#include <isc/region.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/callbacks.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>

#include "dnstest.h"

static void
rdata_fromtext(dns_rdata_t *rdata, const char *rdata_txt,
	       dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
	       isc_buffer_t *target)
{
	char *rdata_txt_mutable;
	isc_lex_t *lex = NULL;
	dns_rdatacallbacks_t callbacks;
	isc_buffer_t source, target_local;
	static char buf[8192]; /* should be large enough for our tests */

	DE_CONST(rdata_txt, rdata_txt_mutable);
	dns_rdatacallbacks_init(&callbacks);
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       isc_lex_create(mctx, strlen(rdata_txt), &lex));
	isc_buffer_init(&source, rdata_txt_mutable, strlen(rdata_txt_mutable));
	isc_buffer_add(&source, strlen(rdata_txt_mutable));
	if (target == NULL) {
		isc_buffer_init(&target_local, buf, sizeof(buf));
		target = &target_local;
	}
	ATF_REQUIRE_EQ(ISC_R_SUCCESS, isc_lex_openbuffer(lex, &source));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdata_fromtext(rdata, rdclass, rdtype, lex,
					  dns_rootname, 0, mctx, target,
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

static void
rdataslab_fromtext(dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		   const char *rdata_texts[], unsigned int nrdata,
		   isc_buffer_t *rdata_buf, isc_region_t *region,
		   dns_cksum_t *cksump, dns_cksum_t *case_cksump)
{
	dns_rdataset_t rdataset;
	dns_rdatalist_t rdatalist;
	unsigned int i;
	dns_rdata_t rdata[16];	/* fixed size of placeholder for simplicity */

	REQUIRE(nrdata < 16);

	dns_rdatalist_init(&rdatalist);
	rdatalist.type = rdtype;
	rdatalist.rdclass = rdclass;

	for (i = 0; i < nrdata; i++) {
		dns_rdata_init(&rdata[i]);
		rdata_fromtext(&rdata[i], rdata_texts[i], rdclass, rdtype,
			       rdata_buf);
		ISC_LIST_APPEND(rdatalist.rdata, &rdata[i], link);
	}

	dns_rdataset_init(&rdataset);
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdatalist_tordataset(&rdatalist, &rdataset));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdataslab_fromrdataset2(&rdataset, mctx, region, 0,
						   cksump, case_cksump));
}

/*
 * Test cases
 */

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
	ATF_REQUIRE_EQ(htons(3 + 97 * 3),
		       dns_name_cksum(name_fromtext("aaa."), ISC_TRUE));
	ATF_REQUIRE_EQ(htons(3 + 65 * 3),
		       dns_name_cksum(name_fromtext("AAA."), ISC_TRUE));

	/*
	 * If it's case insensitive, both should be equal to the checksum of
	 * 'aaa.'
	 */
	ATF_REQUIRE_EQ(htons(3 + 97 * 3),
		       dns_name_cksum(name_fromtext("aaa."), ISC_FALSE));
	ATF_REQUIRE_EQ(htons(3 + 97 * 3),
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
	ATF_REQUIRE_EQ(htons(64000),
		       dns_name_cksum(name_fromtext(long_name), ISC_FALSE));
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
	rdata_fromtext(&rdata, "192.0.2.1", dns_rdataclass_in, dns_rdatatype_a,
		       NULL);
	ATF_REQUIRE_EQ(htons(0xc201), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(0xc201), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_rdata_init(&rdata);
	/* checksum: 0x2001 + 0xdb8 + 0x1 */
	rdata_fromtext(&rdata, "2001:db8::1", dns_rdataclass_in,
		       dns_rdatatype_aaaa, NULL);
	ATF_REQUIRE_EQ(htons(0x2dba), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(0x2dba), dns_rdata_cksum(&rdata, ISC_TRUE));

	/* odd-byte length of data */
	dns_rdata_init(&rdata);
	/* checksum: 0x0261 + 0x6100 (note that 'a' = 0x61) */
	rdata_fromtext(&rdata, "aa", dns_rdataclass_in, dns_rdatatype_txt,
		       NULL);
	ATF_REQUIRE_EQ(htons(0x6361), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(0x6361), dns_rdata_cksum(&rdata, ISC_TRUE));

	/* overflow case */
	dns_rdata_init(&rdata);
	/* checksum: 0x03ff + 0xffff = 0x103fe (overflow) => 0x3ff */
	rdata_fromtext(&rdata, "\\255\\255\\255", dns_rdataclass_in,
		       dns_rdatatype_txt, NULL);
	ATF_REQUIRE_EQ(htons(0x3ff), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(0x3ff), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_rdata_init(&rdata);
	/*
	 * checksum: 0x07ff + 0xf7fc + 0xffff + 0x0005 = 0x1ffff (overflow)
	 *           => 0x10000 (still overflow) => 0x1
	 */
	rdata_fromtext(&rdata, "\\255\\247\\252\\255\\255\\000\\005",
		       dns_rdataclass_in, dns_rdatatype_txt, NULL);
	ATF_REQUIRE_EQ(htons(1), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(1), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_rdata_init(&rdata);
	/*
	 * checksum: 'N'=0x4e, 'n'=0x6e, 's'=0x73, so
	 * (case insensitive): 0x02 + 0x6e + 0x73 = 0xe3
	 * (case sensitive): 0x024e + 0x7300 = 0x754e
	 */
	rdata_fromtext(&rdata, "Ns.", dns_rdataclass_in, dns_rdatatype_ns,
		       NULL);
	ATF_REQUIRE_EQ(htons(0xe3), dns_rdata_cksum(&rdata, ISC_FALSE));
	ATF_REQUIRE_EQ(htons(0x754e), dns_rdata_cksum(&rdata, ISC_TRUE));

	dns_test_end();
}

ATF_TC(rdataslab_cksum);
ATF_TC_HEAD(rdataslab_cksum, tc) {
	atf_tc_set_md_var(tc, "descr", "rdataslab checksum");
}
ATF_TC_BODY(rdataslab_cksum, tc) {
	const char *rdatas[] = {"192.0.2.1", "192.0.2.2"};
	const char *nsrdatas[] = {"Ns."};
	isc_region_t region;
	char buf[8192];	/* fixed size, should be large enough for this test */
	isc_buffer_t rdata_buf;
	dns_cksum_t cksum, case_cksum;

	UNUSED(tc);

	ATF_REQUIRE_EQ(ISC_R_SUCCESS, dns_test_begin(NULL, ISC_FALSE));
	isc_buffer_init(&rdata_buf, buf, sizeof(buf));

	/*
	 * slab from a single RDATA:
	 * checksum: 0xc000 + 0x0201 = 0xc201, case doesn't matter
	 */
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_a, rdatas, 1,
			   &rdata_buf, &region, &cksum, &case_cksum);
	ATF_REQUIRE_EQ(htons(0xc201), cksum);
	ATF_REQUIRE_EQ(htons(0xc201), case_cksum);
	isc_mem_put(mctx, region.base, region.length);

	/*
	 * slab from 2 RDATAs.
	 * checksum: 0xc201 + 0xc000 + 0x0202 = 0x18403 (overflow) => 0x8404
	 */
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_a, rdatas, 2,
			   &rdata_buf, &region, &cksum, &case_cksum);
	ATF_REQUIRE_EQ(htons(0x8404), cksum);
	ATF_REQUIRE_EQ(htons(0x8404), case_cksum);
	isc_mem_put(mctx, region.base, region.length);

	/*
	 * slab for NS RDATA, for checking case sensitiveness.
	 * (see the rdata_cksum test for the expected values)
	 */
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_ns, nsrdatas, 1,
			   &rdata_buf, &region, &cksum, &case_cksum);
	ATF_REQUIRE_EQ(htons(0xe3), cksum);
	ATF_REQUIRE_EQ(htons(0x754e), case_cksum);
	isc_mem_put(mctx, region.base, region.length);

	dns_test_end();
}

ATF_TC(rdataslab_merge);
ATF_TC_HEAD(rdataslab_merge, tc) {
	atf_tc_set_md_var(tc, "descr", "rdataslab merge checksum");
}
ATF_TC_BODY(rdataslab_merge, tc) {
	isc_buffer_t rdata_buf;
	char buf[8192];	/* fixed size, should be large enough for this test */
	const char *rdatas1[] = {"192.0.2.1", "192.0.2.4"};
	const char *rdatas2[] = {"192.0.2.2", "192.0.2.3"};
	const char *rdatas3[] = {"192.0.2.4", "192.0.2.5"};
	const char *rdatas4[] = {"ns.example."};
	const char *rdatas5[] = {"Ns."};
	isc_region_t region1, region2, region3, region4, region5;
	unsigned char *new_slab;
	dns_cksum_t cksum, case_cksum;

	UNUSED(tc);

	ATF_REQUIRE_EQ(ISC_R_SUCCESS, dns_test_begin(NULL, ISC_FALSE));
	isc_buffer_init(&rdata_buf, buf, sizeof(buf));

	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_a, rdatas1, 2,
			   &rdata_buf, &region1, NULL, NULL);
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_a, rdatas2, 2,
			   &rdata_buf, &region2, NULL, NULL);
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_a, rdatas3, 2,
			   &rdata_buf, &region3, NULL, NULL);
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_ns, rdatas4, 1,
			   &rdata_buf, &region4, NULL, NULL);
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_ns, rdatas5, 1,
			   &rdata_buf, &region5, NULL, NULL);

	/*
	 * merge a non-overlapping slab.  the returned checksum should be
	 * that of the merged slab: 0xc202 + 0xc203 => 0x8406
	 */
	new_slab = NULL;
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdataslab_merge2(region1.base, region2.base, 0, mctx,
					    dns_rdataclass_in, dns_rdatatype_a,
					    0, &new_slab, &cksum, &case_cksum));
	isc_mem_put(mctx, new_slab, dns_rdataslab_size(new_slab, 0));
	ATF_REQUIRE_EQ(htons(0x8406), cksum);
	ATF_REQUIRE_EQ(htons(0x8406), case_cksum);

	/*
	 * merge an overlapping slab.  the returned checksum should be
	 * that of the newly merged RDATA (192.0.2.5): 0xc205
	 */
	new_slab = NULL;
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdataslab_merge2(region1.base, region3.base, 0, mctx,
					    dns_rdataclass_in, dns_rdatatype_a,
					    0, &new_slab, &cksum, &case_cksum));
	isc_mem_put(mctx, new_slab, dns_rdataslab_size(new_slab, 0));
	ATF_REQUIRE_EQ(htons(0xc205), cksum);
	ATF_REQUIRE_EQ(htons(0xc205), case_cksum);

	/* Use NS RDATA to check case sensitiveness. */
	new_slab = NULL;
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdataslab_merge2(region4.base, region5.base, 0, mctx,
					    dns_rdataclass_in, dns_rdatatype_ns,
					    0, &new_slab, &cksum, &case_cksum));
	isc_mem_put(mctx, new_slab, dns_rdataslab_size(new_slab, 0));
	ATF_REQUIRE_EQ(htons(0xe3), cksum);
	ATF_REQUIRE_EQ(htons(0x754e), case_cksum);

	isc_mem_put(mctx, region1.base, region1.length);
	isc_mem_put(mctx, region2.base, region2.length);
	isc_mem_put(mctx, region3.base, region3.length);
	isc_mem_put(mctx, region4.base, region4.length);
	isc_mem_put(mctx, region5.base, region5.length);
	dns_test_end();
}

ATF_TC(rdataslab_subtract);
ATF_TC_HEAD(rdataslab_subtract, tc) {
	atf_tc_set_md_var(tc, "descr", "rdataslab subtract checksum");
}
ATF_TC_BODY(rdataslab_subtract, tc) {
	isc_buffer_t rdata_buf;
	char buf[8192];	/* fixed size, should be large enough for this test */
	const char *rdatas1[] = {"ns.example.", "Ns.", "Nss."};
	const char *rdatas2[] = {"ns.", "nss."};
	isc_region_t region1, region2;
	unsigned char *new_slab;
	dns_cksum_t cksum, case_cksum;

	UNUSED(tc);

	ATF_REQUIRE_EQ(ISC_R_SUCCESS, dns_test_begin(NULL, ISC_FALSE));
	isc_buffer_init(&rdata_buf, buf, sizeof(buf));

	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_ns, rdatas1, 3,
			   &rdata_buf, &region1, NULL, NULL);
	rdataslab_fromtext(dns_rdataclass_in, dns_rdatatype_ns, rdatas2, 2,
			   &rdata_buf, &region2, NULL, NULL);

	/*
	 * subtract slab2 from slab1.  The returned checksums are for
	 * "Ns." and "Nss.":
	 * (case insensitive): 0x02 + 0x6e + 0x73 + 0x03 + 0x6e + 0x73 + 0x73
	 * (case sensitive): 0x024e + 0x7300 + 0x034e + 0x7373
	 * Note that, in the case of case-insensitive, the checksum is for
	 * RDATA in slab1.
	 */
	new_slab = NULL;
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_rdataslab_subtract2(region1.base, region2.base, 0,
					       mctx, dns_rdataclass_in,
					       dns_rdatatype_ns, 0, &new_slab,
					       &cksum, &case_cksum));
	isc_mem_put(mctx, new_slab, dns_rdataslab_size(new_slab, 0));
	ATF_REQUIRE_EQ(htons(0x23a), cksum);
	ATF_REQUIRE_EQ(htons(0xec0f), case_cksum);

	isc_mem_put(mctx, region1.base, region1.length);
	isc_mem_put(mctx, region2.base, region2.length);
	dns_test_end();
}

ATF_TC(db_cksum);
ATF_TC_HEAD(db_cksum, tc) {
	atf_tc_set_md_var(tc, "descr", "zone DB checksum");
}
ATF_TC_BODY(db_cksum, tc) {
	dns_db_t *db = NULL;
	dns_cksum_t cksum, case_cksum;

	UNUSED(tc);

	ATF_REQUIRE_EQ(ISC_R_SUCCESS, dns_test_begin(NULL, ISC_FALSE));

	/* create the database.  the initial checksum should be 0. */
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_db_create(mctx, "rbt", name_fromtext("example."),
				     dns_dbtype_zone, dns_rdataclass_in, 0,
				     NULL, &db));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_db_cksum(db, NULL, &cksum, &case_cksum));
	ATF_REQUIRE_EQ(0, cksum);
	ATF_REQUIRE_EQ(0, case_cksum);

	/*
	 * load records from a file.  see the data file for the expected
	 * values.
	 */
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_db_load(db, "testdata/master/cksum.data"));
	ATF_REQUIRE_EQ(ISC_R_SUCCESS,
		       dns_db_cksum(db, NULL, &cksum, &case_cksum));
	ATF_REQUIRE_EQ(htons(0x5001), cksum);
	ATF_REQUIRE_EQ(htons(0x1ad6), case_cksum);

	dns_db_detach(&db);
	dns_test_end();
}

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
	ATF_TP_ADD_TC(tp, name_cksum);
	ATF_TP_ADD_TC(tp, rdata_cksum);
	ATF_TP_ADD_TC(tp, rdataslab_cksum);
	ATF_TP_ADD_TC(tp, rdataslab_merge);
	ATF_TP_ADD_TC(tp, rdataslab_subtract);
	ATF_TP_ADD_TC(tp, db_cksum);

	return (atf_no_error());
}
