#!/usr/bin/env luajit

local snmp = require('snmp')

local internet = snmp.oid '1.3.6.1'

local system = snmp.oid{ internet, '2.1.1' }
local sysUpTimeInstance = snmp.oid{ system, 3, 0 }

local logEntry = snmp.oid{ internet, '2.1.16.9.2.1' }
local logEventIndex = snmp.oid{ logEntry, 1 }
local logIndex = snmp.oid{ logEntry, 2 }
local logTime = snmp.oid{ logEntry, 3 }
local logDescription = snmp.oid{ logEntry, 4 }

local cl = snmp.connect{host=arg[1]}
cl.chunk_size = 25

print('UPTIME', cl:get(sysUpTimeInstance):eval())

for bind in cl:table(logDescription) do
	print(bind.value)
end
