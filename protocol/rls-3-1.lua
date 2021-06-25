--[[
--
-- Dissector for Radio Link Simulation Protocol version 3.1.x
-- (UERANSIM project <https://github.com/aligungr/UERANSIM>).
--
-- CC0-1.0 2021 - Louis Royer (<https://github.com/louisroyer/RLS-wireshark-dissector>)
--
--]]
local rlsProtocol31 = Proto("RLS-3.1", "UERANSIM 3.1.x Radio Link Simulation (RLS) Protocol")
local fields = rlsProtocol31.fields

local msgTypeNames = {
	[0] = "[Reserved]",
	[1] = "Cell Info Request",
	[2] = "Cell Info Response",
	[3] = "PDU Delivery",
}

local pduTypeNames = {
	[0] = "[Reserved]",
	[1] = "RRC",
	[2] = "Data"
}

local rrcMsgTypeNames = {
	[0] = "BCCH-BCH",
	[1] = "BCCH-DL-SCH",
	[2] = "DL-CCCH",
	[3] = "DL-DCCH",
	[4] = "PCCH",
	[5] = "UL-CCCH",
	[6] = "UL-CCCH1",
	[7] = "UL-DCCH",
}

local nrRrcDissectors = {
	[0] = "nr-rrc.bcch.bch",
	[1] = "nr-rrc.bcch.dl.sch",
	[2] = "nr-rrc.dl.ccch",
	[3] = "nr-rrc.dl.dcch",
	[4] = "nr-rrc.pcch",
	[5] = "nr-rrc.ul.ccch",
	[6] = "nr-rrc.ul.ccch1",
	[7] = "nr-rrc.ul.dcch",
}

fields.Version = ProtoField.string("rls.version", "Version")
fields.MsgType = ProtoField.uint8("rls.message_type", "Message Type", base.DEC, msgTypeNames)
fields.Sti = ProtoField.uint64("rls.sti", "Sender Node Temporary ID", base.DEC)
fields.PduType = ProtoField.uint8("rls.pdu_type", "PDU Type", base.DEC, pduTypeNames)
fields.RrcMsgType = ProtoField.uint32("rls.rrc_message_type", "RRC Message Type", base.DEC, rrcMsgTypeNames)
fields.PduLength = ProtoField.uint32("rls.pdu_length", "PDU Length", base.DEC)
fields.PduSessionId = ProtoField.uint32("rls.pdu_session_id", "PDU Session ID", base.DEC)
fields.Dbm = ProtoField.int32("rls.dbm", "RLS Signal Strength (dBm)", base.DEC)
fields.PosX = ProtoField.uint32("rls.pos_x", "RLS Position X", base.DEC)
fields.PosY = ProtoField.uint32("rls.pos_y", "RLS Position Y", base.DEC)
fields.PosZ = ProtoField.uint32("rls.pos_z", "RLS Position Z", base.DEC)
fields.Mcc = ProtoField.uint16("rls.mcc", "MCC", base.DEC)
fields.Mnc = ProtoField.uint16("rls.mnc", "MNC", base.DEC)
fields.LongMnc = ProtoField.bool("rls.long_mnc", "MNC is 3-digit", base.BOOL)
fields.Nci = ProtoField.uint64("rls.nci", "NR Cell Identity", base.HEX)
fields.Tac = ProtoField.uint32("rls.tac", "Tracking Area Code", base.DEC)
fields.GnbName = ProtoField.string("rls.gnb_name", "gNB Name")
fields.LinkIp = ProtoField.string("rls.link_ip", "gNB Link IP")

function rlsProtocol31.dissector(buffer, pinfo, tree)
	if buffer:len() == 0 then return false end
	if buffer(0, 1):uint() ~= 0x03 then return false end
	if buffer(1, 2):uint() > 0x0301 then return false end

	pinfo.cols.protocol = rlsProtocol31.name

	local versionNumber = buffer(1, 1):uint() .. "." .. buffer(2, 1):uint() .. "." .. buffer(3, 1):uint()
	local subtree = tree:add(rlsProtocol31, buffer(), "UERANSIM Radio Link Simulation (RLS) protocol")

	subtree:add(fields.Version, buffer(1, 3), versionNumber)
	subtree:add(fields.MsgType, buffer(4, 1))
	local msgType = buffer(4, 1):uint()

	pinfo.cols.info = msgTypeNames[msgType]
	subtree:add(fields.Sti, buffer(5, 8))

	if msgType == 1 then -- Cell Info Request
		subtree:add(fields.PosX, buffer(13,4))
		subtree:add(fields.PosY, buffer(17,4))
		subtree:add(fields.PosZ, buffer(21,4))
	elseif msgType == 2 then -- Cell Info Response
		subtree:add(fields.Mcc, buffer(13,2))
		local mnc_tree = subtree:add(rlsProtocol31, buffer(15,3), "MNC: "..tostring(buffer(15,2):uint()))
		mnc_tree:add(fields.Mnc, buffer(15,2))
		mnc_tree:add(fields.LongMnc, buffer(17,1))
		subtree:add(fields.Nci, buffer(18,8))
		subtree:add(fields.Tac, buffer(26,4))
		subtree:add(fields.Dbm, buffer(30,4))
		local gnbNameLength = buffer(34,4):uint()
		subtree:add(fields.GnbName, buffer(38,gnbNameLength))
		local linkIpLength = buffer(38+gnbNameLength,4):uint()
		subtree:add(fields.LinkIp, buffer(42+gnbNameLength,linkIpLength))
	elseif msgType == 3 then -- PDU Delivery
		subtree:add(fields.PduType, buffer(13,1))
		local pduType = buffer(13,1):uint()
		local pduLength = buffer(14,4):uint()
		local payloadLength = buffer(18+pduLength,4):uint()
		if pduType == 1 then -- RRC
			local rrcMsgType = buffer(22+pduLength,payloadLength):uint()
			subtree:add(fields.RrcMsgType, buffer(22+pduLength,payloadLength))
			subtree:add(fields.PduLength, buffer(14,4))
			-- Old versions of Wireshark (< 3.0.0) cannot handle NR-RRC correctly
			local dissector
			local function get_dissector()
				dissector = Dissector.get(nrRrcDissectors[rrcMsgType])
			end
			if pcall(get_dissector) then
				dissector:call(buffer(18, pduLength):tvb(), pinfo, tree)
			else
				pinfo.cols.info = msgTypeNames[msgType]
					.. " - " .. rrcMsgTypeNames[rrcMsgType]
					.. " - Cannot decode"
				return false
			end
		elseif pduType == 2 then -- DATA
			subtree:add(fields.PduSessionId, buffer(22+pduLength,payloadLength))
			subtree:add(fields.PduLength, buffer(14,4))
			Dissector.get("ip"):call(buffer(18,pduLength):tvb(), pinfo, tree)
		end
	end
end

function rlsProtocol31.init()
	local rls = DissectorTable.get("rls")
	rls:add(0x0301, rlsProtocol31)
	local udp_port = DissectorTable.get("udp.port")
	udp_port:add_for_decode_as(rlsProtocol31)
end
