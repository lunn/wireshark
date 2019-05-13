/* packet-netlink-generic.c
 * Dissector for Linux Generic Netlink.
 *
 * Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include "packet-netlink.h"

/*
 * Documentation:
 * https://wiki.linuxfoundation.org/networking/generic_netlink_howto#message-format
 * include/uapi/linux/netlink.h
 * include/uapi/linux/genetlink.h
 *
 * For the meaning of fields in genlmsghdr, see genlmsg_put in
 * net/netlink/genetlink.c, note that it has no user-specific message header
 * (genl_ctrl.hdr_size==0).
 */

void proto_register_netlink_generic(void);
void proto_reg_handoff_netlink_generic(void);

typedef struct {
	struct packet_netlink_data *data;
	int             encoding; /* copy of data->encoding */

	/* Values parsed from the attributes (only valid in this packet). */
	guint16         family_id;
	const guint8   *family_name;
} genl_ctrl_info_t;

typedef struct {
	struct packet_netlink_data *data;
	int             encoding; /* copy of data->encoding */
} genl_ethtool_info_t;

/* from include/uapi/linux/genetlink.h */
enum {
	WS_CTRL_CMD_UNSPEC,
	WS_CTRL_CMD_NEWFAMILY,
	WS_CTRL_CMD_DELFAMILY,
	WS_CTRL_CMD_GETFAMILY,
	WS_CTRL_CMD_NEWOPS,
	WS_CTRL_CMD_DELOPS,
	WS_CTRL_CMD_GETOPS,
	WS_CTRL_CMD_NEWMCAST_GRP,
	WS_CTRL_CMD_DELMCAST_GRP,
	WS_CTRL_CMD_GETMCAST_GRP,
};
enum ws_genl_ctrl_attr {
	WS_CTRL_ATTR_UNSPEC,
	WS_CTRL_ATTR_FAMILY_ID,
	WS_CTRL_ATTR_FAMILY_NAME,
	WS_CTRL_ATTR_VERSION,
	WS_CTRL_ATTR_HDRSIZE,
	WS_CTRL_ATTR_MAXATTR,
	WS_CTRL_ATTR_OPS,
	WS_CTRL_ATTR_MCAST_GROUPS,
};

enum ws_genl_ctrl_op_attr {
	WS_CTRL_ATTR_OP_UNSPEC,
	WS_CTRL_ATTR_OP_ID,
	WS_CTRL_ATTR_OP_FLAGS,
};

enum ws_genl_ctrl_group_attr {
	WS_CTRL_ATTR_MCAST_GRP_UNSPEC,
	WS_CTRL_ATTR_MCAST_GRP_NAME,
	WS_CTRL_ATTR_MCAST_GRP_ID,
};

#define WS_GENL_ID_CTRL 0x10
#define GENL_CTRL_NAME "nlctrl"

static const value_string genl_ctrl_cmds[] = {
	{ WS_CTRL_CMD_UNSPEC,           "CTRL_CMD_UNSPEC" },
	{ WS_CTRL_CMD_NEWFAMILY,        "CTRL_CMD_NEWFAMILY" },
	{ WS_CTRL_CMD_DELFAMILY,        "CTRL_CMD_DELFAMILY" },
	{ WS_CTRL_CMD_GETFAMILY,        "CTRL_CMD_GETFAMILY" },
	{ WS_CTRL_CMD_NEWOPS,           "CTRL_CMD_NEWOPS" },
	{ WS_CTRL_CMD_DELOPS,           "CTRL_CMD_DELOPS" },
	{ WS_CTRL_CMD_GETOPS,           "CTRL_CMD_GETOPS" },
	{ WS_CTRL_CMD_NEWMCAST_GRP,     "CTRL_CMD_NEWMCAST_GRP" },
	{ WS_CTRL_CMD_DELMCAST_GRP,     "CTRL_CMD_DELMCAST_GRP" },
	{ WS_CTRL_CMD_GETMCAST_GRP,     "CTRL_CMD_GETMCAST_GRP" },
	{ 0, NULL }
};

static const value_string genl_ctrl_attr_vals[] = {
	{ WS_CTRL_ATTR_UNSPEC,          "CTRL_ATTR_UNSPEC" },
	{ WS_CTRL_ATTR_FAMILY_ID,       "CTRL_ATTR_FAMILY_ID" },
	{ WS_CTRL_ATTR_FAMILY_NAME,     "CTRL_ATTR_FAMILY_NAME" },
	{ WS_CTRL_ATTR_VERSION,         "CTRL_ATTR_VERSION" },
	{ WS_CTRL_ATTR_HDRSIZE,         "CTRL_ATTR_HDRSIZE" },
	{ WS_CTRL_ATTR_MAXATTR,         "CTRL_ATTR_MAXATTR" },
	{ WS_CTRL_ATTR_OPS,             "CTRL_ATTR_OPS" },
	{ WS_CTRL_ATTR_MCAST_GROUPS,    "CTRL_ATTR_MCAST_GROUPS" },
	{ 0, NULL }
};

static const value_string genl_ctrl_op_attr_vals[] = {
	{ WS_CTRL_ATTR_OP_UNSPEC,       "CTRL_ATTR_OP_UNSPEC" },
	{ WS_CTRL_ATTR_OP_ID,           "CTRL_ATTR_OP_ID" },
	{ WS_CTRL_ATTR_OP_FLAGS,        "CTRL_ATTR_OP_FLAGS" },
	{ 0, NULL }
};

static const value_string genl_ctrl_group_attr_vals[] = {
	{ WS_CTRL_ATTR_MCAST_GRP_UNSPEC, "CTRL_ATTR_MCAST_GRP_UNSPEC" },
	{ WS_CTRL_ATTR_MCAST_GRP_NAME,  "CTRL_ATTR_MCAST_GRP_NAME" },
	{ WS_CTRL_ATTR_MCAST_GRP_ID,    "CTRL_ATTR_MCAST_GRP_ID" },
	{ 0, NULL }
};

static int proto_netlink_generic;

static dissector_handle_t netlink_generic;
static dissector_handle_t netlink_generic_ctrl;
static dissector_handle_t netlink_generic_ethtool;

static dissector_table_t genl_dissector_table;

static header_field_info *hfi_netlink_generic = NULL;

#define NETLINK_GENERIC_HFI_INIT HFI_INIT(proto_netlink_generic)

static gint ett_netlink_generic = -1;
static gint ett_genl_ctrl_attr = -1;
static gint ett_genl_ctrl_ops = -1;
static gint ett_genl_ctrl_ops_attr = -1;
static gint ett_genl_ctrl_op_flags = -1;
static gint ett_genl_ctrl_groups = -1;
static gint ett_genl_ctrl_groups_attr = -1;
static gint ett_genl_nested_attr = -1;
static gint ett_genl_ethtool_act_cable_test = -1;
static gint ett_genl_ethtool_cmd_event = -1;
static gint ett_genl_ethtool_cmd_event_dev_attr = -1;
static gint ett_genl_ethtool_cmd_event_cable_test = -1;
static gint ett_genl_ethtool_cable_test_result = -1;
static gint ett_genl_ethtool_cable_test_fault_length = -1;
static gint ett_genl_ethtool_dev_attr = -1;

/*
 * Maps family IDs (integers) to family names (strings) within a capture file.
 */
static wmem_map_t *genl_family_map;


static header_field_info hfi_genl_ctrl_op_id NETLINK_GENERIC_HFI_INIT =
	{ "Operation ID", "genl.ctrl.op_id", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags NETLINK_GENERIC_HFI_INIT =
	{ "Operation Flags", "genl.ctrl.op_flags", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_admin_perm NETLINK_GENERIC_HFI_INIT =
	{ "GENL_ADMIN_PERM", "genl.ctrl.op_flags.admin_perm", FT_BOOLEAN, 32,
	  NULL, 0x01, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_do NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_DO", "genl.ctrl.op_flags.cmd_cap_do", FT_BOOLEAN, 32,
	  NULL, 0x02, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_dump NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_DUMP", "genl.ctrl.op_flags.cmd_cap_dump", FT_BOOLEAN, 32,
	  NULL, 0x04, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_cmd_cap_haspol NETLINK_GENERIC_HFI_INIT =
	{ "GENL_CMD_CAP_HASPOL", "genl.ctrl.op_flags.cmd_cap_haspol", FT_BOOLEAN, 32,
	  NULL, 0x08, NULL, HFILL };

static header_field_info hfi_genl_ctrl_op_flags_uns_admin_perm NETLINK_GENERIC_HFI_INIT =
	{ "GENL_UNS_ADMIN_PERM", "genl.ctrl.op_flags.uns_admin_perm", FT_BOOLEAN, 32,
	  NULL, 0x10, NULL, HFILL };

static const int *genl_ctrl_op_flags_fields[] = {
	&hfi_genl_ctrl_op_flags_admin_perm.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_do.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_dump.id,
	&hfi_genl_ctrl_op_flags_cmd_cap_haspol.id,
	&hfi_genl_ctrl_op_flags_uns_admin_perm.id,
	NULL
};

static int
dissect_genl_ctrl_ops_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_op_attr type = (enum ws_genl_ctrl_op_attr) nla_type;
	genl_ctrl_info_t *info = (genl_ctrl_info_t *) data;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	guint32 value;

	switch (type) {
	case WS_CTRL_ATTR_OP_UNSPEC:
		break;
	case WS_CTRL_ATTR_OP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_op_id, tvb, offset, 4, info->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OP_FLAGS:
		if (len == 4) {
			guint64 op_flags;
			/* XXX it would be nice if the flag names are appended to the tree */
			proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, &hfi_genl_ctrl_op_flags,
				ett_genl_ctrl_op_flags, genl_ctrl_op_flags_fields, info->encoding, BMT_NO_FALSE, &op_flags);
			proto_item_append_text(tree, ": 0x%08x", (guint32)op_flags);
			proto_item_append_text(ptree, ", flags=0x%08x", (guint32)op_flags);
			offset += 4;
		}
		break;
	}

	return offset;
}


static header_field_info hfi_genl_ctrl_group_name NETLINK_GENERIC_HFI_INIT =
	{ "Group Name", "genl.ctrl.group_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_group_id NETLINK_GENERIC_HFI_INIT =
	{ "Group ID", "genl.ctrl.group_id", FT_UINT32, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_genl_ctrl_groups_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_group_attr type = (enum ws_genl_ctrl_group_attr) nla_type;
	genl_ctrl_info_t *info = (genl_ctrl_info_t *) data;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	guint32 value;
	const guint8 *strval;

	switch (type) {
	case WS_CTRL_ATTR_MCAST_GRP_UNSPEC:
		break;
	case WS_CTRL_ATTR_MCAST_GRP_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_genl_ctrl_group_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &strval);
		proto_item_append_text(tree, ": %s", strval);
		proto_item_append_text(ptree, ", name=%s", strval);
		offset += len;
		break;
	case WS_CTRL_ATTR_MCAST_GRP_ID:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_group_id, tvb, offset, 4, info->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			proto_item_append_text(ptree, ", id=%u", value);
			offset += 4;
		}
		break;
	}

	return offset;
}


static header_field_info hfi_genl_ctrl_family_id NETLINK_GENERIC_HFI_INIT =
	{ "Family ID", "genl.ctrl.family_id", FT_UINT16, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_family_name NETLINK_GENERIC_HFI_INIT =
	{ "Family Name", "genl.ctrl.family_name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ctrl_version NETLINK_GENERIC_HFI_INIT =
	{ "Version", "genl.ctrl.version", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Family-specific version number", HFILL };

static header_field_info hfi_genl_ctrl_hdrsize NETLINK_GENERIC_HFI_INIT =
	{ "Header Size", "genl.ctrl.hdrsize", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Size of family-specific header", HFILL };

static header_field_info hfi_genl_ctrl_maxattr NETLINK_GENERIC_HFI_INIT =
	{ "Maximum Attributes", "genl.ctrl.maxattr", FT_UINT32, BASE_DEC,
	  NULL, 0x00, "Maximum number of attributes", HFILL };

static header_field_info hfi_genl_ctrl_ops_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl.ops_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_op_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

static header_field_info hfi_genl_ctrl_groups_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl.groups_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_group_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

static int
dissect_genl_ctrl_attrs(tvbuff_t *tvb, void *data, proto_tree *tree, int nla_type, int offset, int len)
{
	enum ws_genl_ctrl_attr type = (enum ws_genl_ctrl_attr) nla_type;
	genl_ctrl_info_t *info = (genl_ctrl_info_t *) data;
	guint32 value;

	switch (type) {
	case WS_CTRL_CMD_UNSPEC:
		break;
	case WS_CTRL_ATTR_FAMILY_ID:
		if (len == 2) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_family_id, tvb, offset, 2, info->encoding, &value);
			proto_item_append_text(tree, ": %#x", value);
			info->family_id = value;
			offset += 2;
		}
		break;
	case WS_CTRL_ATTR_FAMILY_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_genl_ctrl_family_name, tvb, offset, len, ENC_ASCII, wmem_packet_scope(), &info->family_name);
		proto_item_append_text(tree, ": %s", info->family_name);
		offset += len;
		break;
	case WS_CTRL_ATTR_VERSION:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_version, tvb, offset, 4, info->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_HDRSIZE:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_hdrsize, tvb, offset, 4, info->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_MAXATTR:
		if (len == 4) {
			proto_tree_add_item_ret_uint(tree, &hfi_genl_ctrl_maxattr, tvb, offset, 4, info->encoding, &value);
			proto_item_append_text(tree, ": %u", value);
			offset += 4;
		}
		break;
	case WS_CTRL_ATTR_OPS:
		offset = dissect_netlink_attributes_array(tvb, &hfi_genl_ctrl_ops_attr, ett_genl_ctrl_ops, ett_genl_ctrl_ops_attr, info, info->data, tree, offset, len, dissect_genl_ctrl_ops_attrs);
		break;
	case WS_CTRL_ATTR_MCAST_GROUPS:
		offset = dissect_netlink_attributes_array(tvb, &hfi_genl_ctrl_groups_attr, ett_genl_ctrl_groups, ett_genl_ctrl_groups_attr, info, info->data, tree, offset, len, dissect_genl_ctrl_groups_attrs);
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ctrl_cmd NETLINK_GENERIC_HFI_INIT =
	{ "Command", "genl.ctrl.cmd", FT_UINT8, BASE_DEC,
	  VALS(genl_ctrl_cmds), 0x00, "Generic Netlink command", HFILL };

static header_field_info hfi_genl_ctrl_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ctrl_attr", FT_UINT16, BASE_DEC,
	  VALS(genl_ctrl_attr_vals), NLA_TYPE_MASK, NULL, HFILL };

static int
dissect_genl_ctrl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	genl_ctrl_info_t info;
	int offset;

	if (!genl_info) {
		return 0;
	}

	info.data = genl_info->data;
	info.encoding = genl_info->encoding;
	info.family_id = 0;
	info.family_name = NULL;

	offset = dissect_genl_header(tvb, genl_info, &hfi_genl_ctrl_cmd);

	dissect_netlink_attributes(tvb, &hfi_genl_ctrl_attr, ett_genl_ctrl_attr, &info, info.data, genl_info->genl_tree, offset, -1, dissect_genl_ctrl_attrs);

	/*
	 * Remember association of dynamic ID with the family name such that
	 * future packets can be linked to a protocol.
	 * Do not allow overwriting our control protocol.
	 */
	if (info.family_id && info.family_id != WS_GENL_ID_CTRL && info.family_name) {
		wmem_map_insert(genl_family_map, GUINT_TO_POINTER(info.family_id), wmem_strdup(wmem_file_scope(), info.family_name));
	}

	return tvb_captured_length(tvb);
}

/* from include/uapi/linux/ethtool_netlink.h */
enum sw_ethtool_cmd_events {
	WS_ETHNL_CMD_NOP,
	WS_ETHNL_CMD_EVENT,		/* only for notifications */
	WS_ETHNL_CMD_GET_STRSET,
	WS_ETHNL_CMD_SET_STRSET,	/* only for reply */
	WS_ETHNL_CMD_GET_INFO,
	WS_ETHNL_CMD_SET_INFO,		/* only for reply */
	WS_ETHNL_CMD_GET_SETTINGS,
	WS_ETHNL_CMD_SET_SETTINGS,
	WS_ETHNL_CMD_GET_PARAMS,
	WS_ETHNL_CMD_SET_PARAMS,
	WS_ETHNL_CMD_ACT_NWAY_RST,
	WS_ETHNL_CMD_ACT_PHYS_ID,
	WS_ETHNL_CMD_ACT_RESET,
	WS_ETHNL_CMD_GET_RXFLOW,
	WS_ETHNL_CMD_SET_RXFLOW,
	WS_ETHNL_CMD_ACT_CABLE_TEST,
};

enum ws_ethtool_dev_attrs {
        WS_ETHTOOL_A_DEV_UNSPEC,
        WS_ETHTOOL_A_DEV_INDEX,
        WS_ETHTOOL_A_DEV_NAME,
};

enum ws_ethtool_cmd_events {
	WS_ETHTOOL_A_EVENT_UNSPEC,
	WS_ETHTOOL_A_EVENT_NEWDEV,
	WS_ETHTOOL_A_EVENT_DELDEV,
	WS_ETHTOOL_A_EVENT_RENAMEDEV,
	WS_ETHTOOL_A_EVENT_CABLE_TEST,
};

enum ws_ethtool_cable_test_pair {
	WS_ETHTOOL_A_CABLE_PAIR_0,
	WS_ETHTOOL_A_CABLE_PAIR_1,
	WS_ETHTOOL_A_CABLE_PAIR_2,
	WS_ETHTOOL_A_CABLE_PAIR_3,
};

enum ws_ethtool_cable_test_code {
	WS_ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,
	WS_ETHTOOL_A_CABLE_RESULT_CODE_OK,
	WS_ETHTOOL_A_CABLE_RESULT_CODE_OPEN,
	WS_ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
	WS_ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
};

enum ws_ethtool_cable_test_fault_length {
	WS_ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
	WS_ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
	WS_ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
};

enum ws_ethtool_cable_test_result {
	WS_ETHTOOL_A_CABLE_RESULT_UNSPEC,
	WS_ETHTOOL_A_CABLE_RESULT_PAIR,
	WS_ETHTOOL_A_CABLE_RESULT_CODE,
};

enum ws_ethtool_cmd_events_cable_test {
	WS_ETHTOOL_A_CABLE_TEST_EVENT_UNSPEC,
	WS_ETHTOOL_A_CABLE_TEST_EVENT_DEV,
	WS_ETHTOOL_A_CABLE_TEST_EVENT_RESULT,
	WS_ETHTOOL_A_CABLE_TEST_EVENT_FAULT_LENGTH,
	WS_ETHTOOL_A_CABLE_TEST_EVENT_LENGTH,
};

enum {
	WS_ETHTOOL_A_NEWDEV_UNSPEC,
	WS_ETHTOOL_A_NEWDEV_DEV,
};

enum ws_ethtool_act_cable_test_attrs {
        WS_ETHTOOL_A_CABLE_TEST_UNSPEC,
        WS_ETHTOOL_A_CABLE_TEST_DEV,
};

#define WS_GENL_ID_ETHTOOL 0x14
#define GENL_ETHTOOL_NAME "ethtool"

static const value_string genl_ethtool_cmds[] = {
	{ WS_ETHNL_CMD_NOP,		"ETHNL_CMD_NOP" },
	{ WS_ETHNL_CMD_EVENT,		"ETHNL_CMD_EVENT" },
	{ WS_ETHNL_CMD_GET_STRSET,	"ETHNL_CMD_GET_STRSET" },
	{ WS_ETHNL_CMD_SET_STRSET,	"ETHNL_CMD_SET_STRSET" },
	{ WS_ETHNL_CMD_GET_INFO,	"ETHNL_CMD_GET_INFO" },
	{ WS_ETHNL_CMD_SET_INFO,	"ETHNL_CMD_SET_INFO" },
	{ WS_ETHNL_CMD_GET_SETTINGS,	"ETHNL_CMD_GET_SETTINGS" },
	{ WS_ETHNL_CMD_SET_SETTINGS,	"ETHNL_CMD_SET_SETTINGS" },
	{ WS_ETHNL_CMD_GET_PARAMS,	"ETHNL_CMD_GET_PARAMS" },
	{ WS_ETHNL_CMD_SET_PARAMS,	"ETHNL_CMD_SET_PARAMS" },
	{ WS_ETHNL_CMD_ACT_NWAY_RST,	"ETHNL_CMD_ACT_NWAY_RST" },
	{ WS_ETHNL_CMD_ACT_PHYS_ID,	"ETHNL_CMD_ACT_PHYS_ID" },
	{ WS_ETHNL_CMD_ACT_RESET,	"ETHNL_CMD_ACT_RESET" },
	{ WS_ETHNL_CMD_GET_RXFLOW,	"ETHNL_CMD_GET_RXFLOW" },
	{ WS_ETHNL_CMD_SET_RXFLOW,	"ETHNL_CMD_SET_RXFLOW" },
	{ WS_ETHNL_CMD_ACT_CABLE_TEST,	"ETHNL_CMD_ACT_CABLE_TEST" },
	{ 0, NULL }
};

static const value_string genl_ethtool_cmd_events[] = {
	{ WS_ETHTOOL_A_EVENT_UNSPEC,	"ETHTOOL_A_EVENT_UNSPEC", },
	{ WS_ETHTOOL_A_EVENT_NEWDEV,	"ETHTOOL_A_EVENT_NEWDEV", },
	{ WS_ETHTOOL_A_EVENT_DELDEV,	"ETHTOOL_A_EVENT_DELDEV", },
	{ WS_ETHTOOL_A_EVENT_RENAMEDEV,	"ETHTOOL_A_EVENT_RENAMEDEV", },
	{ WS_ETHTOOL_A_EVENT_CABLE_TEST,"ETHTOOL_A_EVENT_CABLE_TEST", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cable_test_pair[] = {
	{ WS_ETHTOOL_A_CABLE_PAIR_0,	"PAIR 0", },
	{ WS_ETHTOOL_A_CABLE_PAIR_1,	"PAIR 1", },
	{ WS_ETHTOOL_A_CABLE_PAIR_2,	"PAIR 2", },
	{ WS_ETHTOOL_A_CABLE_PAIR_3,	"PAIR_3", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cable_test_code[] = {
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,	"UNSPEC", },
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE_OK,		"OK", },
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE_OPEN,		"OPEN", },
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,	"SAME_SHORT", },
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,	"CROSS_SHORT", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cable_test_fault_length[] = {
	{ WS_ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
	  "ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC", },
	{ WS_ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
	  "ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR", },
	{ WS_ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
	  "ETHTOOL_A_CABLE_FAULT_LENGTH_CM", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cable_test_result[] = {
	{ WS_ETHTOOL_A_CABLE_RESULT_UNSPEC,	"ETHTOOL_A_CABLE_RESULT_UNSPEC", },
	{ WS_ETHTOOL_A_CABLE_RESULT_PAIR,	"ETHTOOL_A_CABLE_RESULT_PAIR", },
	{ WS_ETHTOOL_A_CABLE_RESULT_CODE,	"ETHTOOL_A_CABLE_RESULT_CODE", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cmd_events_cable_test[] = {
	{ WS_ETHTOOL_A_CABLE_TEST_EVENT_UNSPEC,
	  "ETHTOOL_A_CABLE_TEST_EVENT_UNSPEC", },
	{ WS_ETHTOOL_A_CABLE_TEST_EVENT_DEV,
	  "ETHTOOL_A_CABLE_TEST_EVENT_DEV", },
	{ WS_ETHTOOL_A_CABLE_TEST_EVENT_RESULT,
	  "ETHTOOL_A_CABLE_TEST_EVENT_RESULT", },
	{ WS_ETHTOOL_A_CABLE_TEST_EVENT_FAULT_LENGTH,
	  "ETHTOOL_A_CABLE_TEST_EVENT_FAULT_LENGTH", },
	{ WS_ETHTOOL_A_CABLE_TEST_EVENT_LENGTH,
	  "ETHTOOL_A_CABLE_TEST_EVENT_LENGTH", },
	{ 0, NULL }
};

static const value_string genl_ethtool_cmd_events_dev[] = {
	{ WS_ETHTOOL_A_NEWDEV_UNSPEC,	"ETHTOOL_A_*DEV_UNSPEC", },
	{ WS_ETHTOOL_A_NEWDEV_DEV,	"ETHTOOL_A_*DEV_DEV", },
	{ 0, NULL }
};

static const value_string genl_ethtool_dev_attrs[] = {

	{ WS_ETHTOOL_A_DEV_INDEX,	"ETHTOOL_A_DEV_INDEX", },
	{ WS_ETHTOOL_A_DEV_NAME,	"ETHTOOL_A_DEV_NAME", },
	{ 0, NULL }
};

static const value_string genl_ethtool_act_cable_test_attrs[] = {
	{ WS_ETHTOOL_A_CABLE_TEST_UNSPEC,	"ETHTOOL_A_CABLE_TEST_UNSPEC", },
	{ WS_ETHTOOL_A_CABLE_TEST_DEV,		"ETHTOOL_A_CABLE_TEST_DEV", },
};

static header_field_info hfi_genl_ethtool_dev_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.dev", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_dev_attrs), NLA_TYPE_MASK, NULL, HFILL };

static header_field_info hfi_genl_ethtool_dev_index NETLINK_GENERIC_HFI_INIT =
	{ "Device Index", "genl.ethtool_dev.index", FT_UINT32, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_ethtool_dev_name NETLINK_GENERIC_HFI_INIT =
	{ "Device Name", "genl.ethtool_dev.name", FT_STRINGZ, STR_ASCII,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_genl_ethtool_dev_attrs(tvbuff_t *tvb,
			       void *data _U_, proto_tree *tree,
			       int nla_type, int offset, int len)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_dev_attrs attr = (enum ws_ethtool_dev_attrs)type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	const guint8 *name;
	guint32 index;

	switch (attr) {
	case WS_ETHTOOL_A_DEV_UNSPEC:
		break;
	case WS_ETHTOOL_A_DEV_INDEX:
		proto_tree_add_item_ret_uint(tree, &hfi_genl_ethtool_dev_index,
					     tvb, offset, 4, info->encoding,
					     &index);
		proto_item_append_text(tree, ": %d", index);
		proto_item_append_text(ptree, ", ifindex %d", index);
		offset += 4;
		break;
	case WS_ETHTOOL_A_DEV_NAME:
		proto_tree_add_item_ret_string(tree, &hfi_genl_ethtool_dev_name,
					       tvb, offset, len, info->encoding,
					       wmem_packet_scope(), &name);
		proto_item_append_text(tree, ": %s", name);
		proto_item_append_text(ptree, ", %s", name);
		offset += len;
		break;
	};

	return offset;
}

static int
dissect_genl_ethtool_act_cable_test(tvbuff_t *tvb, void *data, proto_tree *tree,
				    int nla_type, int offset, int len)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_act_cable_test_attrs attr =
		(enum ws_ethtool_act_cable_test_attrs)type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;

	switch (attr) {
	case WS_ETHTOOL_A_CABLE_TEST_UNSPEC:
		break;
	case WS_ETHTOOL_A_CABLE_TEST_DEV:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_dev_attr,
			ett_genl_ethtool_dev_attr,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_dev_attrs);
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cable_test_result NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.cmd_event.cable_test.result",
	  FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cable_test_result), NLA_TYPE_MASK, NULL,
	  HFILL };

static header_field_info hfi_genl_ethtool_cable_test_result_pair NETLINK_GENERIC_HFI_INIT =
	{ "Cable Pair", "genl.ethtool_dev.cmd_event.cable_test.result.pair",
	  FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cable_test_pair), 0x00, NULL, HFILL };

static header_field_info hfi_genl_ethtool_cable_test_result_code NETLINK_GENERIC_HFI_INIT =
	{ "Code", "genl.ethtool_dev.cmd_event.cable_test.result.code",
	  FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cable_test_code), 0x00, NULL, HFILL };

static int
dissect_genl_ethtool_cable_test_result(tvbuff_t *tvb, void *data,
				       proto_tree *tree, int nla_type,
				       int offset, int len _U_)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_cable_test_result attr =
		(enum ws_ethtool_cable_test_result) type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	const char *code_str;
	guint32 pair;
	guint32 code;

	switch (attr) {
	case WS_ETHTOOL_A_CABLE_RESULT_UNSPEC:
		break;
	case WS_ETHTOOL_A_CABLE_RESULT_PAIR:
		proto_tree_add_item_ret_uint(
			tree, &hfi_genl_ethtool_cable_test_result_pair,
			tvb, offset, 1, info->encoding, &pair);
		proto_item_append_text(tree, ": %d", pair);
		proto_item_append_text(ptree, ", pair %d", pair);
		offset += 1;
		break;
	case WS_ETHTOOL_A_CABLE_RESULT_CODE:
		proto_tree_add_item_ret_uint(
			tree, &hfi_genl_ethtool_cable_test_result_code,
			tvb, offset, 1, info->encoding, &code);
		code_str = try_val_to_str(code, genl_ethtool_cable_test_code);
		proto_item_append_text(tree, ": %s", code_str);
		proto_item_append_text(ptree, ", code %s", code_str);
		offset += 1;
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cable_test_fault_length NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.cmd_event.cable_test.fault_length",
	  FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cable_test_fault_length), NLA_TYPE_MASK, NULL,
	  HFILL };

static header_field_info hfi_genl_ethtool_cable_test_fault_length_pair NETLINK_GENERIC_HFI_INIT =
	{ "Cable Pair", "genl.ethtool_dev.cmd_event.cable_test.fault_length.pair",
	  FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cable_test_pair), 0x00, NULL, HFILL };

static header_field_info hfi_genl_ethtool_cable_test_fault_length_cm NETLINK_GENERIC_HFI_INIT =
	{ "Length", "genl.ethtool_dev.cmd_event.cable_test.fault_length.cm",
	  FT_UINT16, BASE_DEC,
	  NULL, 0x00, NULL, HFILL };

static int
dissect_genl_ethtool_cable_test_fault_length(tvbuff_t *tvb, void *data,
					     proto_tree *tree, int nla_type,
					     int offset, int len _U_)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_cable_test_fault_length attr =
		(enum ws_ethtool_cable_test_fault_length) type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;
	proto_tree *ptree = proto_tree_get_parent_tree(tree);
	guint32 pair;
	guint32 length;

	switch (attr) {
	case WS_ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC:
		break;
	case WS_ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR:
		proto_tree_add_item_ret_uint(
			tree, &hfi_genl_ethtool_cable_test_fault_length_pair,
			tvb, offset, 1, info->encoding, &pair);
		proto_item_append_text(tree, ": %d", pair);
		proto_item_append_text(ptree, ", pair %d", pair);
		offset += 1;
		break;
	case WS_ETHTOOL_A_CABLE_FAULT_LENGTH_CM:
		proto_tree_add_item_ret_uint(
			tree, &hfi_genl_ethtool_cable_test_fault_length_cm,
			tvb, offset, 2, info->encoding, &length);
		proto_item_append_text(tree, ": %d cm", length);
		proto_item_append_text(ptree, ", length %d cm", length);
		offset += 1;
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cmd_event_cable_test NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.cmd_event.cable_test", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cmd_events_cable_test), NLA_TYPE_MASK, NULL,
	  HFILL };

static int
dissect_genl_ethtool_cmd_event_cable_test(tvbuff_t *tvb,
					  void *data, proto_tree *tree,
					  int nla_type, int offset, int len)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_cmd_events_cable_test attr =
		(enum ws_ethtool_cmd_events_cable_test)type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;

	switch (attr) {
	case WS_ETHTOOL_A_CABLE_TEST_EVENT_UNSPEC:
		break;
	case WS_ETHTOOL_A_CABLE_TEST_EVENT_DEV:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_dev_attr,
			ett_genl_ethtool_dev_attr,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_dev_attrs);
		break;
	case WS_ETHTOOL_A_CABLE_TEST_EVENT_RESULT:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_cable_test_result,
			ett_genl_ethtool_cable_test_result,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_cable_test_result);
		break;
	case WS_ETHTOOL_A_CABLE_TEST_EVENT_FAULT_LENGTH:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_cable_test_fault_length,
			ett_genl_ethtool_cable_test_fault_length,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_cable_test_fault_length);
		break;
	default:
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cmd_event_dev_attr NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.cmd_event.dev", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cmd_events_dev), NLA_TYPE_MASK, NULL, HFILL };

/* NEWDEV, DELDEV, and RENAMEDEV all use the same format */
static int
dissect_genl_ethtool_cmd_event_dev_attrs(tvbuff_t *tvb,
					 void *data, proto_tree *tree,
					 int nla_type, int offset, int len)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_act_cable_test_attrs attr =
		(enum ws_ethtool_act_cable_test_attrs)type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;

	switch (attr) {
	case WS_ETHTOOL_A_NEWDEV_UNSPEC:
		break;
	case WS_ETHTOOL_A_NEWDEV_DEV:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_dev_attr,
			ett_genl_ethtool_dev_attr,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_dev_attrs);
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cmd_event NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.cmd_event", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cmd_events), NLA_TYPE_MASK, NULL, HFILL };

static int
dissect_genl_ethtool_cmd_event(tvbuff_t *tvb,
			       void *data , proto_tree *tree,
			       int nla_type, int offset, int len)
{
	int type = nla_type & NLA_TYPE_MASK;
	enum ws_ethtool_cmd_events attr = (enum ws_ethtool_cmd_events) type;
	genl_ethtool_info_t *info = (genl_ethtool_info_t *) data;

	switch (attr) {
	case WS_ETHTOOL_A_EVENT_UNSPEC:
		break;
	case WS_ETHTOOL_A_EVENT_NEWDEV:
	case WS_ETHTOOL_A_EVENT_DELDEV:
	case WS_ETHTOOL_A_EVENT_RENAMEDEV:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_cmd_event_dev_attr,
			ett_genl_ethtool_cmd_event_dev_attr,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_cmd_event_dev_attrs);
		break;
	case WS_ETHTOOL_A_EVENT_CABLE_TEST:
		offset += dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_cmd_event_cable_test,
			ett_genl_ethtool_cmd_event_cable_test,
			info, info->data, tree, offset, len,
			dissect_genl_ethtool_cmd_event_cable_test);
		break;
	}

	return offset;
}

static header_field_info hfi_genl_ethtool_cmd NETLINK_GENERIC_HFI_INIT =
	{ "Command", "genl.ethtool.cmd", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_cmds), 0x00, "Generic Netlink command", HFILL };

static header_field_info hfi_genl_ethtool_act_cable_test NETLINK_GENERIC_HFI_INIT =
	{ "Type", "genl.ethtool.act_cable_test", FT_UINT8, BASE_DEC,
	  VALS(genl_ethtool_act_cable_test_attrs), NLA_TYPE_MASK, NULL, HFILL };

static int
dissect_genl_ethtool(tvbuff_t *tvb, packet_info *pinfo _U_,
		     proto_tree *tree _U_, void *data)
{
	genl_info_t *genl_info = (genl_info_t *) data;
	genl_ethtool_info_t info;
	guint8 cmd;
	int offset;

	if (!genl_info) {
		return 0;
	}

	info.data = genl_info->data;
	info.encoding = genl_info->encoding;

	offset = dissect_genl_header(tvb, genl_info, &hfi_genl_ethtool_cmd);

	cmd = tvb_get_guint8(tvb, 0);

	switch (cmd) {
	case WS_ETHNL_CMD_EVENT:
		dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_cmd_event,
			ett_genl_ethtool_cmd_event,
			&info, info.data,
			genl_info->genl_tree, offset, -1,
			dissect_genl_ethtool_cmd_event);
		break;
	case WS_ETHNL_CMD_ACT_CABLE_TEST:
		dissect_netlink_attributes(
			tvb, &hfi_genl_ethtool_act_cable_test,
			ett_genl_ethtool_act_cable_test,
			&info, info.data,
			genl_info->genl_tree, offset, -1,
			dissect_genl_ethtool_act_cable_test);
		break;
	}

	return tvb_captured_length(tvb);
}


static header_field_info hfi_genl_family_id NETLINK_GENERIC_HFI_INIT =
	{ "Family ID", "genl.family_id", FT_UINT8, BASE_HEX,
	  NULL, 0x00, NULL, HFILL };

static header_field_info hfi_genl_cmd NETLINK_GENERIC_HFI_INIT =
	{ "Command", "genl.cmd", FT_UINT8, BASE_DEC,
	  NULL, 0x00, "Generic Netlink command", HFILL };

static header_field_info hfi_genl_version NETLINK_GENERIC_HFI_INIT =
	{ "Family Version", "genl.version", FT_UINT8, BASE_DEC,
	  NULL, 0x00, "Family-specfic version", HFILL };

static header_field_info hfi_genl_reserved NETLINK_GENERIC_HFI_INIT =
	{ "Reserved", "genl.reserved", FT_NONE, BASE_NONE,
	  NULL, 0x00, NULL, HFILL };

int dissect_genl_header(tvbuff_t *tvb, genl_info_t *genl_info, header_field_info *hfi_cmd)
{
	int offset = 0;

	if (!hfi_cmd) {
		hfi_cmd = &hfi_genl_cmd;
	}
	proto_tree_add_item(genl_info->genl_tree, hfi_cmd, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(genl_info->genl_tree, &hfi_genl_version, tvb, offset, 1, ENC_NA);
	offset++;
	proto_tree_add_item(genl_info->genl_tree, &hfi_genl_reserved, tvb, offset, 2, genl_info->encoding);
	offset += 2;
	return offset;
}

static int
dissect_netlink_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *_data)
{
	struct packet_netlink_data *data = (struct packet_netlink_data *)_data;
	genl_info_t info;
	proto_tree *nlmsg_tree;
	proto_item *pi, *pi_type;
	const char *family_name;
	tvbuff_t *next_tvb;
	int offset = 0;

	DISSECTOR_ASSERT(data && data->magic == PACKET_NETLINK_MAGIC);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Netlink generic");
	col_clear(pinfo->cinfo, COL_INFO);

	pi = proto_tree_add_item(tree, proto_registrar_get_nth(proto_netlink_generic), tvb, 0, -1, ENC_NA);
	nlmsg_tree = proto_item_add_subtree(pi, ett_netlink_generic);

	/* Netlink message header (nlmsghdr) */
	offset = dissect_netlink_header(tvb, nlmsg_tree, offset, data->encoding, &hfi_genl_family_id, &pi_type);
	family_name = (const char *)wmem_map_lookup(genl_family_map, GUINT_TO_POINTER(data->type));
	proto_item_append_text(pi_type, " (%s)", family_name ? family_name : "Unknown");

	/* Populate info from Generic Netlink message header (genlmsghdr) */
	info.data = data;
	info.encoding = data->encoding;
	info.genl_tree = nlmsg_tree;
	info.cmd = tvb_get_guint8(tvb, offset);

	/* Optional user-specific message header and optional message payload. */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	/* Try subdissector if there is a payload. */
	if (tvb_reported_length_remaining(tvb, offset + 4)) {
		if (family_name) {
			int ret;
			/* Invoke subdissector with genlmsghdr present. */
			ret = dissector_try_string(genl_dissector_table, family_name, next_tvb, pinfo, tree, &info);
			if (ret) {
				return ret;
			}
		}
	}

	/* No subdissector added the genl header, do it now. */
	offset = dissect_genl_header(next_tvb, &info, NULL);
	if (tvb_reported_length_remaining(tvb, offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return offset;
}

static void
genl_init(void)
{
	/* Add fixed family entry (0x10 maps to "nlctrl"). */
	wmem_map_insert(genl_family_map, GUINT_TO_POINTER(WS_GENL_ID_CTRL), GENL_CTRL_NAME);
	/* Add fixed family entry (0x14 maps to "ethtool"). */
	wmem_map_insert(genl_family_map, GUINT_TO_POINTER(WS_GENL_ID_ETHTOOL),
			GENL_ETHTOOL_NAME);
}

void
proto_register_netlink_generic(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_genl_family_id,
		&hfi_genl_cmd,
		&hfi_genl_version,
		&hfi_genl_reserved,
		&hfi_genl_ctrl_attr,
		/* Controller */
		&hfi_genl_ctrl_cmd,
		&hfi_genl_ctrl_family_id,
		&hfi_genl_ctrl_family_name,
		&hfi_genl_ctrl_version,
		&hfi_genl_ctrl_hdrsize,
		&hfi_genl_ctrl_maxattr,
		&hfi_genl_ctrl_ops_attr,
		&hfi_genl_ctrl_groups_attr,
		&hfi_genl_ctrl_op_id,
		&hfi_genl_ctrl_op_flags,
		&hfi_genl_ctrl_op_flags_admin_perm,
		&hfi_genl_ctrl_op_flags_cmd_cap_do,
		&hfi_genl_ctrl_op_flags_cmd_cap_dump,
		&hfi_genl_ctrl_op_flags_cmd_cap_haspol,
		&hfi_genl_ctrl_op_flags_uns_admin_perm,
		&hfi_genl_ctrl_group_name,
		&hfi_genl_ctrl_group_id,
		&hfi_genl_ethtool_cmd,
		&hfi_genl_ethtool_act_cable_test,
		&hfi_genl_ethtool_dev_attr,
		&hfi_genl_ethtool_dev_index,
		&hfi_genl_ethtool_dev_name,
		&hfi_genl_ethtool_cmd_event_dev_attr,
		&hfi_genl_ethtool_cmd_event_cable_test,
		&hfi_genl_ethtool_cable_test_result,
		&hfi_genl_ethtool_cable_test_result_pair,
		&hfi_genl_ethtool_cable_test_result_code,
		&hfi_genl_ethtool_cable_test_fault_length,
		&hfi_genl_ethtool_cable_test_fault_length_pair,
		&hfi_genl_ethtool_cable_test_fault_length_cm,
		&hfi_genl_ethtool_cmd_event,
	};
#endif

	static gint *ett[] = {
		&ett_netlink_generic,
		&ett_genl_ctrl_attr,
		&ett_genl_ctrl_ops,
		&ett_genl_ctrl_ops_attr,
		&ett_genl_ctrl_op_flags,
		&ett_genl_ctrl_groups,
		&ett_genl_ctrl_groups_attr,
		&ett_genl_nested_attr,
		&ett_genl_ethtool_act_cable_test,
		&ett_genl_ethtool_cmd_event,
		&ett_genl_ethtool_cmd_event_dev_attr,
		&ett_genl_ethtool_cmd_event_cable_test,
		&ett_genl_ethtool_dev_attr,
		&ett_genl_ethtool_cable_test_result,
		&ett_genl_ethtool_cable_test_fault_length,
	};

	proto_netlink_generic = proto_register_protocol("Linux Generic Netlink protocol", "genl", "genl");
	hfi_netlink_generic = proto_registrar_get_nth(proto_netlink_generic);

	proto_register_fields(proto_netlink_generic, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	netlink_generic = create_dissector_handle(dissect_netlink_generic, proto_netlink_generic);
	netlink_generic_ctrl = create_dissector_handle(dissect_genl_ctrl, proto_netlink_generic);
	netlink_generic_ethtool = create_dissector_handle(dissect_genl_ethtool, proto_netlink_generic);
	genl_dissector_table = register_dissector_table(
		"genl.family",
		"Linux Generic Netlink family name",
		proto_netlink_generic, FT_STRING,
		BASE_NONE
	);

	genl_family_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

	register_init_routine(genl_init);
}

void
proto_reg_handoff_netlink_generic(void)
{
	dissector_add_string("genl.family", GENL_CTRL_NAME, netlink_generic_ctrl);
	dissector_add_string("genl.family", GENL_ETHTOOL_NAME, netlink_generic_ethtool);
	dissector_add_uint("netlink.protocol", WS_NETLINK_GENERIC, netlink_generic);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
