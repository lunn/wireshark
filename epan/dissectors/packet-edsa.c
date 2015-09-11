/* packet-edsa.c
 * Routines for EDSA packet disassembly. EDSA is used by Marvell Switches
 * to allow the host to direct packets out specific ports of the switch.
 *
 * $Id$
 *
 * By Andrew Lunn <andrew@lunn.ch>
 * Copyright 2015 Andrew Lunn
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/arptypes.h>
#include "packet-eth.h"
#include "packet-ieee8023.h"

static int proto_edsa = -1;
static int hf_edsa_tag = -1;
static int hf_edsa_tagged = -1;
static int hf_edsa_dev = -1;
static int hf_edsa_port = -1;
static int hf_edsa_code = -1;
static int hf_edsa_trunk = -1;
static int hf_edsa_cfi = -1;
static int hf_edsa_prio = -1;
static int hf_edsa_vid = -1;
static int hf_edsa_ethtype = -1;
static int hf_edsa_trailer = -1;
static int hf_edsa_len = -1;

static gint ett_edsa = -1;
static expert_field ei_edsa_len = EI_INIT;

static dissector_handle_t ethertype_handle;

#define TAG_TO_CPU	0
#define TAG_FROM_CPU	1
#define TAG_FORWARD	3

static const value_string tag_vals[] = {
	{ TAG_TO_CPU, "To_CPU" },
	{ TAG_FROM_CPU, "From_CPU" },
	{ TAG_FORWARD, "Forward" },
	{0, NULL}};

#define CODE_BDPU	0
#define CODE_IGMP_MLD	2
#define CODE_ARP_MIRROR	4

static const value_string code_vals[]={
	{ CODE_BDPU, "BDPU" },
	{ CODE_IGMP_MLD, "IGMP/MLD" },
	{ CODE_ARP_MIRROR, "APR_Mirror" },
	{0, NULL}};

#define EDSA_HEADER_SIZE  8

static void
dissect_edsa(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 edsa_tag;
	guint8 edsa_tagged;
	guint8 edsa_dev;
	guint8 edsa_port;
	guint8 edsa_trunk;
	guint8 edsa_cfi;
	guint8 edsa_prio;
	guint8 edsa_vid;
	guint8 edsa_code;
	guint16 edsa_ethtype;
	gboolean is_802_2;

	proto_tree  *edsa_tree = NULL;
	proto_item  *ti;

	edsa_tag 	= tvb_get_bits8(tvb, (8 * 2) + 0 , 2);
	edsa_tagged 	= tvb_get_bits8(tvb, (8 * 2) + 2, 1);
	edsa_dev 	= tvb_get_bits8(tvb, (8 * 2) + 3, 5);
	edsa_port 	= tvb_get_bits8(tvb, (8 * 3) + 0, 5);
	edsa_trunk 	= tvb_get_bits8(tvb, (8 * 3) + 5, 1);
	edsa_cfi 	= tvb_get_bits8(tvb, (8 * 3) + 7, 0);
	edsa_prio	= tvb_get_bits8(tvb, (8 * 4) + 0, 3);
	edsa_vid 	= tvb_get_bits16(tvb, (8 * 4) + 4, 12, TRUE);

	edsa_code	= (tvb_get_bits8(tvb, (8 * 3) + 5, 2) << 2 |
			   tvb_get_bits8(tvb, (8 * 4) + 3, 1));
	edsa_ethtype	= tvb_get_ntohs(tvb, 6);

	if (tree) {
		ti = proto_tree_add_protocol_format(
			tree, proto_edsa, tvb, 0, EDSA_HEADER_SIZE,
			"EtherType Distributed Switch Architecture, %s Dev: %d Port: %d VID: %d",
			val_to_str(edsa_tag, tag_vals, "tag %d"),
			edsa_dev, edsa_port, edsa_vid);
		edsa_tree = proto_item_add_subtree(ti, ett_edsa);
		proto_tree_add_uint(edsa_tree, hf_edsa_tag,
				    tvb, 2, 1, edsa_tag);
		switch (edsa_tag) {
		case TAG_TO_CPU:
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_tagged, tvb, 2, 1,
				edsa_tagged);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_dev, tvb, 2, 1, edsa_dev);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_port, tvb, 3, 1, edsa_port);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_vid, tvb, 4, 2, edsa_vid);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_code, tvb, 3, 2, edsa_code);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_prio, tvb, 4, 1, edsa_prio);
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_cfi, tvb, 3, 1, edsa_cfi);
			break;
		case TAG_FROM_CPU:
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_tagged, tvb, 2, 1,
				edsa_tagged);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_dev, tvb, 2, 1, edsa_dev);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_port, tvb, 3, 1, edsa_port);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_vid, tvb, 4, 2, edsa_vid);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_prio, tvb, 4, 1, edsa_prio);
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_cfi, tvb, 3, 1, edsa_cfi);
			break;
		case TAG_FORWARD:
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_tagged, tvb, 2, 1,
				edsa_tagged);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_dev, tvb, 2, 1, edsa_dev);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_port, tvb, 3, 1, edsa_port);
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_trunk, tvb, 3, 1,
				edsa_trunk);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_vid, tvb, 4, 2, edsa_vid);
			proto_tree_add_uint(
				edsa_tree, hf_edsa_prio, tvb, 4, 1, edsa_prio);
			proto_tree_add_boolean(
				edsa_tree, hf_edsa_cfi, tvb, 3, 1, edsa_cfi);
			break;
		}
	}
	if (edsa_ethtype <= IEEE_802_3_MAX_LEN) {
		/* Is there an 802.2 layer? I can tell by looking at
		   the first 2 bytes after the VLAN header. If they
		   are 0xffff, then what follows the VLAN header is an
		   IPX payload, meaning no 802.2.  (IPX/SPX is they
		   only thing that can be contained inside a straight
		   802.3 packet, so presumably the same applies for
		   Ethernet VLAN packets). A non-0xffff value means
		   that there's an 802.2 layer inside the VLAN
		   layer */
		is_802_2 = TRUE;

		/* Don't throw an exception for this check (even a
		 * BoundsError) */
		if (tvb_captured_length_remaining(tvb, 8) >= 2) {
			if (tvb_get_ntohs(tvb, 8) == 0xffff) {
				is_802_2 = FALSE;
			}
			dissect_802_3(edsa_ethtype, is_802_2, tvb, 8, pinfo,
				      tree, edsa_tree, hf_edsa_len,
				      hf_edsa_trailer, &ei_edsa_len, 0);
		}
	} else {
		ethertype_data_t ethertype_data;

		ethertype_data.etype = edsa_ethtype;
		ethertype_data.offset_after_ethertype = 8;
		ethertype_data.fh_tree = edsa_tree;
		ethertype_data.etype_id = hf_edsa_ethtype;
		ethertype_data.trailer_id = hf_edsa_trailer;
		ethertype_data.fcs_len = 0;

		call_dissector_with_data(ethertype_handle, tvb, pinfo, tree,
					 &ethertype_data);
  }
}

void
proto_register_edsa(void)
{
	static hf_register_info hf[] = {
		{ &hf_edsa_tag,
		  { "Tag",		"edsa.tag",
		    FT_UINT8,		BASE_DEC,
		    VALS(tag_vals),	0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_tagged,
		  { "VLAN Tagged",	"edsa.tagged",
		    FT_BOOLEAN,     	8,
		    NULL,     		0x20,
		    NULL, HFILL }},

		{ &hf_edsa_dev,
		  { "Device",		"edsa.device",
		    FT_UINT8,		BASE_DEC,
		    NULL,		0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_port,
		  { "Port",		"edsa.port",
		    FT_UINT8,		BASE_DEC,
		    NULL,		0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_vid,
		  { "VLAN ID",		"edsa.vid",
		    FT_UINT16,		BASE_DEC,
		    NULL,		0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_code,
		  { "Code",		"edsa.code",
		    FT_UINT8,		BASE_DEC,
		    VALS(code_vals),	0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_trunk,
		  { "trunk",		"edsa.trunk",
		    FT_BOOLEAN,     	8,
		    NULL,     		4,
		    NULL,		HFILL }},

		{ &hf_edsa_prio,
		  { "802.1Q Priority",	"edsa.prio",
		    FT_UINT8,		BASE_DEC,
		    NULL,		0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_cfi,
		  { "CFI",		"edsa.cfi",
		    FT_BOOLEAN,     	8,
		    NULL,     		0x01,
		    NULL,		HFILL }},

		/* registered here but handled in packet-ethertype.c */
		{ &hf_edsa_ethtype,
		  { "EthType", 		"edsa.ethtype",
		    FT_UINT16, 		BASE_HEX,
		    VALS(etype_vals),	0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_len,
		  { "Length", 		"edsa.len",
		    FT_UINT16, 		BASE_DEC,
		    NULL, 		0x0,
		    NULL,		HFILL }},

		{ &hf_edsa_trailer,
		  { "Trailer", 		"edsa.trailer",
		    FT_BYTES, 		BASE_NONE,
		    NULL, 		0x0,
		    "Ethernet Trailer or Checksum", HFILL }},
	};

	static gint *ett[] = {
		&ett_edsa,
	};

	static ei_register_info ei[] = {
		{ &ei_edsa_len,
		  { "edsa.len.past_end",
		    PI_MALFORMED, PI_ERROR,
		    "Length field value goes past the end of the payload",
		    EXPFILL }
		},
	};

	expert_module_t* expert_edsa;

	proto_edsa = proto_register_protocol(
		"Ether type Distributed Switch Architecture",
		"EDSA", "edsa");
	proto_register_field_array(proto_edsa, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_edsa = expert_register_protocol(proto_edsa);
	expert_register_field_array(expert_edsa, ei, array_length(ei));

	register_dissector( "edsa" , dissect_edsa, proto_edsa );
}

void
proto_reg_handoff_edsa(void)
{
  dissector_handle_t edsa_handle;

  ethertype_handle = find_dissector("ethertype");
  edsa_handle = find_dissector("edsa");

  dissector_add_uint("ethertype", ETHERTYPE_EDSA, edsa_handle);
}
