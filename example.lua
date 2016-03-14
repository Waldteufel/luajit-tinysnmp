#!/usr/bin/env luajit

local snmp = require('snmp')
local ber = require('ber')
local ByteBuffer = require('ByteBuffer')

local internet = snmp.oid '1.3.6.1'

local system = snmp.oid{ internet, '2.1.1' }
local sysUpTimeInstance = snmp.oid{ system, 3, 0 }

local logEntry = snmp.oid{ internet, '2.1.16.9.2.1' }
local logEventIndex = snmp.oid{ logEntry, 1 }
local logIndex = snmp.oid{ logEntry, 2 }
local logTime = snmp.oid{ logEntry, 3 }
local logDescription = snmp.oid{ logEntry, 4 }

local hubSecurity = snmp.oid '.1.3.6.1.4.1.11.2.14.2.10'
local hpSecAuthAddress = snmp.oid{ hubSecurity, 5, 1, 3, 1 }

local function format_mac(buf)
	local buf = ByteBuffer.new(buf)
	local res = {}
	while buf:remaining_len() > 0 do
		table.insert(res, string.format("%02x", buf:read()))
	end
	return table.concat(res, ':')
end

local cl = snmp.connect{host=arg[1]}
cl.chunk_size = 25

print('UPTIME', cl:get(sysUpTimeInstance):eval())
print()

print('MAC ADDRESSES')
for idx, bind in cl:table(hpSecAuthAddress) do
	local port = ber.read_vlq(ByteBuffer.new(idx))
	print(port, format_mac(bind.value))
end
print()

print('SYSLOG')
for _, bind in cl:table(logDescription) do
	print(bind.value)
end
