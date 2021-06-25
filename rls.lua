--[[
--
-- Dissector for Radio Link Simulation Protocol
-- (UERANSIM project <https://github.com/aligungr/UERANSIM>).
--
-- CC0-1.0 2021 - Louis Royer (<https://github.com/louisroyer/RLS-wireshark-dissector>)
--
--]]

local pluginVersion = "1.1.1"
-- Update the following when adding new versions
local latestVersion = 0x0302
local oldestVersion = 0x0301

local rlsProtocol = Proto("RLS", "UERANSIM Radio Link Simulation (RLS) Protocol")
set_plugin_info({
	version = pluginVersion,
	author = "Louis Royer",
	repository = "https://github.com/louisroyer/RLS-wireshark-dissector",
	description = "Dissector for Radio Link Simulation Protocol"
})

-- Create a DissectorTable to register dissector for each version of RLS
DissectorTable.new("rls", "RLS version", ftypes.UINT32, base.HEX, rlsProtocol)

-- Preferences
rlsProtocol.prefs.udp_port = Pref.uint("RLS UDP port", 4997, "UDP port for RLS")

-- Add version field
local fields = rlsProtocol.fields
fields.Version = ProtoField.string("rls.version", "Version")

function rlsProtocol.dissector(buffer, pinfo, tree)
	-- Generic check
	if buffer:len() == 0 then return end
	if buffer(0, 1):uint() ~= 0x03 then return end

	pinfo.cols.protocol = rlsProtocol.name

	local version = buffer(1,2):uint()
	local subprotocol = DissectorTable.get("rls"):get_dissector(version)
	if subprotocol == nil then
		if version > latestVersion then
			-- fallback to latest version
			version = latestVersion
		elseif version < oldestVersion then
			-- fallback to oldest version
			version = oldestVersion
		end
		subprotocol = DissectorTable.get("rls"):get_dissector(version)
		if subprotocol == nil then
			local versionNumber = buffer(1, 1):uint() .. "." .. buffer(2, 1):uint() .. "." .. buffer(3, 1):uint()
			local subtree = tree:add(rlsProtocol, buffer(), "UERANSIM Radio Link Simulation (RLS) protocol")
			pinfo.cols.info = "Unsupported version - Cannot decode"
			subtree:add(fields.Version, buffer(1, 3), versionNumber)
			return 4
		end
	end
	subprotocol:call(buffer():tvb(), pinfo, tree)
end

function rlsProtocol.init()
	-- Export protocol
	local udp_port = DissectorTable.get("udp.port")
	udp_port:add(rlsProtocol.prefs.udp_port, rlsProtocol)
	udp_port:add_for_decode_as(rlsProtocol)
end
