std = "lua52+wireshark"
unused_args = false
allow_defined_top = true
max_line_length = 120

stds.wireshark = {
	read_globals = {
		"Dissector",
		"DissectorTable",
		"Pref",
		"Proto",
		"ProtoField",
		"base",
		"ftypes",
	}
}
