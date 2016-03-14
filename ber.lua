#!/usr/bin/env luajit

local bit = require('bit')
local ByteBuffer = require('ByteBuffer')

-- This implements the ASN.1 Binary Encoding Rules.

local ber = {}

ber.INTEGER = 0x02
ber.OCTET_STRING = 0x04
ber.NULL = 0x05
ber.OBJECT_IDENTIFIER = 0x06
ber.SEQUENCE = 0x30

function ber.read_vlq(p)
	local c = p:read()
	local v = 0
	while bit.band(c, 0x80) ~= 0 do
		v = (v + bit.band(c, 0x7f)) * 128
		c = p:read()
	end
	v = v + c
	return v
end

function ber.encode_vlq(v)
	if v < 128 then return string.char(v) end

	local buf = string.char(v % 128)
	while v >= 1 do
		v = v / 128
		buf = string.char(128 + v % 128) .. buf
	end
	return buf
end

function ber.read_len(p)
	local c = p:read()
	if bit.band(c, 0x80) == 0 then return c end

	local v = 0
	local n = bit.band(c, 0x7f)
	for i = 1,n do
		c = p:read()
		v = v * 256 + c
	end
	return v
end

function ber.encode_len(v)
	if v < 128 then return string.char(v) end

	local buf = ''
	while v >= 1 do
		buf = string.char(v % 256) .. buf
		v = v / 256
	end

	local n = string.len(buf)
	if n > 127 then error('cannot encode length') end
	return string.char(128 + n) .. buf
end

function ber.read_tag(p)
	local c = p:read()
	if bit.band(c, 31) == 31 then
		return {c, ber.read_vlq(p)}
	else
		return c
	end
end

function ber.encode_tag(v)
	if type(v) == 'table' then
		if bit.band(v[1], 31) == 31 then
			return string.char(v[1]) .. ber.encode_vlq(v[2])
		else
			error('long tag not indicated')
		end
	else
		return string.char(v)
	end
end

function ber.read_lv(p)
	local len = ber.read_len(p)
	local buf = ByteBuffer.new(p, len)
	p:skip(len)
	return buf
end

function ber.encode_lv(...)
	v = table.concat({...})
	return ber.encode_len(string.len(v)) .. v
end

function ber.read_tlv(p)
	local tag = ber.read_tag(p)
	local buf = ber.read_lv(p)
	return tag, buf
end

function ber.encode_tlv(tag, ...)
	return ber.encode_tag(tag) .. ber.encode_lv(...)
end

return ber
