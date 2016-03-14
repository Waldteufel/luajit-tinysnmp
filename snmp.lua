#!/usr/bin/env luajit

local socket = require('socket')
local ber = require('ber')
local ByteBuffer = require('ByteBuffer')

local snmp = {}

snmp.Counter32 = 0x41
snmp.Unsigned32 = 0x42
snmp.TimeTicks = 0x43

snmp.NO_SUCH_INSTANCE = 0x81
snmp.END_OF_MIB_VIEW = 0x82

snmp.PDU_GET = 0xA0
snmp.PDU_GETNEXT = 0xA1
snmp.PDU_REPLY = 0xA2
snmp.PDU_GETBULK = 0xA5

function snmp.oid(arg)
	local res = ''
	local iter, state

	local arg_type = type(arg)
	if arg_type == 'string' then
		iter, state = string.gmatch(arg, "%d+")
		local n1 = tonumber(iter(state))
		local n2 = tonumber(iter(state))
		res = string.char(40 * n1 + n2)
	elseif arg_type == 'table' then
		res = arg[1]
		if type(arg[2]) == 'string' then
			iter, state = string.gmatch(arg[2], "%d+")
		else
			state = { idx = 1 }
			iter = function(state)
				state.idx = state.idx + 1
				return arg[state.idx]
			end
		end
	end
	while true do
		local n = iter(state)
		if n == nil then break end
		res = res .. ber.encode_vlq(tonumber(n))
	end
	return res
end

function snmp.format_oid(buf)
	buf = ByteBuffer.new(buf)
	local n = ber.read_vlq(buf)
	local res = string.format('.%d.%d', n / 40, n % 40)
	while buf:remaining_len() > 0 do
		res = res .. string.format('.%d', ber.read_vlq(buf))
	end
	return res
end

function snmp.match_oid(oid, base)
	oid = ByteBuffer.new(oid)
	base = ByteBuffer.new(base)

	while base:remaining_len() > 0 do
		if ber.read_vlq(oid) ~= ber.read_vlq(base) then
			return nil
		end
	end
	return oid:freeze()
end


local Varbind = {}
local Varbind_mt = { __index = Varbind }

function Varbind_mt:__tostring()
	return string.format('%s = %d : %s', snmp.format_oid(self.oid), self.tag, self:eval())
end

function Varbind.new(self)
	return setmetatable(self, Varbind_mt)
end

function Varbind:eval()
	if self.tag == ber.NULL or self.tag == snmp.NO_SUCH_INSTANCE then
		return nil
	elseif self.tag == ber.INTEGER then
		return ber.read_vlq(ByteBuffer.new(self.value))
	elseif self.tag == snmp.Counter32
	or self.tag == snmp.Unsigned32
	or self.tag == snmp.TimeTicks then
		return bit.bswap(ByteBuffer.new(self.value):read_int32())
	else
		return tostring(self.value)
	end
end


local SNMPClient = {}
local SNMPClient_mt = { __index = SNMPClient }

function SNMPClient.new(args)
	local self = {}
	self.community = args.community

	if self.community == nil then
		for line in io.lines(os.getenv('HOME') .. '/.snmp/snmp.conf') do
			self.community = string.match(line, 'defCommunity (%w+)') or self.community
		end
	end

	if self.community == nil then
		error('missing community string')
	end

	self.request_id = 0
	self.chunk_size = 10
	self.socket = socket.udp()
	self.socket:setpeername(args.host, args.port or 161)
	self.socket:settimeout(1)
	return setmetatable(self, SNMPClient_mt)
end

local function read_specific(p, tag)
	local t, v = ber.read_tlv(p)
	if t ~= tag then
		error('expected tag ' .. tostring(tag))
	end
	return v
end

local function next_varbind(buf)
	if buf:remaining_len() <= 0 then return nil end

	local seq = read_specific(buf, ber.SEQUENCE)
	local oid = read_specific(seq, ber.OBJECT_IDENTIFIER)
	local tag, value = ber.read_tlv(seq)
	return Varbind.new{ oid = oid:freeze(), tag = tag, value = value:freeze() }
end

function SNMPClient:request(args)
	args.request_id = self.request_id
	self.request_id = self.request_id + 1

	for i = 1,#args do
		local x = args[i]
		if getmetatable(x) == Varbind_mt then
			args[i] = ber.encode_tlv(ber.SEQUENCE,
				ber.encode_tlv(ber.OBJECT_IDENTIFIER, x.oid),
				ber.encode_tlv(x.tag, x.value)
			)
		else
			args[i] = ber.encode_tlv(ber.SEQUENCE,
				ber.encode_tlv(ber.OBJECT_IDENTIFIER, tostring(x)),
				ber.encode_tlv(ber.NULL, '')
			)
		end
	end

	local pkt = ber.encode_tlv(ber.SEQUENCE,
		ber.encode_tlv(ber.INTEGER, ber.encode_vlq(1)),
		ber.encode_tlv(ber.OCTET_STRING, self.community),
		ber.encode_tlv(args.pdu_tag,
			ber.encode_tlv(ber.INTEGER, ber.encode_vlq(args.request_id)),
			ber.encode_tlv(ber.INTEGER, ber.encode_vlq(args.n1 or 0)),
			ber.encode_tlv(ber.INTEGER, ber.encode_vlq(args.n2 or 0)),
			ber.encode_tlv(ber.SEQUENCE, table.concat(args))
		)
	)

	self.socket:send(pkt)

	do
		::retry::
		local pkt = self.socket:receive()
		if pkt == nil then error('timeout') end
		local buf = read_specific(ByteBuffer.new(pkt), ber.SEQUENCE)

		local version = ber.read_vlq(read_specific(buf, ber.INTEGER))
		if version ~= 1 then goto retry end

		local community = tostring(read_specific(buf, ber.OCTET_STRING))
		if community ~= self.community then goto retry end

		local pdu_tag = ber.read_tag(buf)
		if pdu_tag ~= snmp.PDU_REPLY then goto retry end
		buf = ber.read_lv(buf)

		local request_id = ber.read_vlq(read_specific(buf, ber.INTEGER))
		if request_id ~= args.request_id then goto retry end

		local err = ber.read_vlq(read_specific(buf, ber.INTEGER))
		local err_idx = ber.read_vlq(read_specific(buf, ber.INTEGER))
		buf = read_specific(buf, ber.SEQUENCE)

		return next_varbind, buf
	end
end

function SNMPClient:get_raw(args)
	args.pdu_tag = snmp.PDU_GET
	return self:request(args)
end

function SNMPClient:getnext_raw(args)
	args.pdu_tag = snmp.PDU_GETNEXT
	return self:request(args)
end

function SNMPClient:getbulk_raw(args)
	args.pdu_tag = snmp.PDU_GETBULK
	args.n1 = args.n1 or (#args - 1)
	args.n2 = args.n2 or 10
	return self:request(args)
end


function SNMPClient:get(...)
	local reply = {}
	for bind in self:get_raw({ ... }) do
		table.insert(reply, bind)
	end
	return unpack(reply)
end


function SNMPClient:getnext(oid)
	local next_bind, buf = self:getnext_raw({ oid })
	return next_bind(buf)
end

local function walk_next(state)
	local bind = state.method(state.self, state.args)

	state.method = SNMPClient.getnext_raw
	state.args[1] = bind.oid

	if bind.tag == snmp.END_OF_MIB_VIEW then
		return nil
	elseif bind.tag == snmp.NO_SUCH_INSTANCE then
		return walk_next(state)
	else
		return bind
	end
end

function SNMPClient:walk(oid)
	return walk_next, {
		self = self,
		method = SNMPClient.get_raw,
		args = { oid }
	}
end


function SNMPClient:getbulk(...)
	local args = { ... }
	args.n1 = #args - 1
	args.n2 = self.chunk_size
	return self:getbulk_raw(args)
end

local function bulkwalk_next(state)
	if state.buf:remaining_len() > 0 then
		local bind = next_varbind(state.buf)
		state.args[1] = bind.oid
		if bind.tag == snmp.END_OF_MIB_VIEW then
			return nil
		elseif bind.tag == snmp.NO_SUCH_INSTANCE then
			return bulkwalk_next(state)
		else
			return bind
		end
	else
		local _, buf = state.method(state.self, state.args)
		state.method = SNMPClient.getbulk_raw
		state.args.n2 = state.self.chunk_size
		state.buf = buf
		return bulkwalk_next(state)
	end
end

function SNMPClient:bulkwalk(oid)
	return bulkwalk_next, {
		self = self,
		method = SNMPClient.get_raw,
		args = { oid },
		buf = ByteBuffer.new('')
	}
end


function table_next(state)
	local res = {}
	local s = state[1]
	table.insert(res, s.f(s.buf))
	local index = snmp.match_oid(res[1].oid, state.base)
	if index == nil then
		return nil
	end
	for i = 2,#state do
		s = state[i]
		table.insert(res, s.f(s.buf))
	end
	return index, unpack(res)
end

function SNMPClient:table(...)
	local state = {...}
	state.base = state[1]
	for i = 1,#state do
		local f, buf = self:bulkwalk(state[i])
		state[i] = { f = f, buf = buf }
	end
	return table_next, state
end

snmp.connect = SNMPClient.new

return snmp
