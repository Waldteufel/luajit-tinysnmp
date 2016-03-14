#!/usr/bin/env luajit

local bit = require('bit')
local ffi = require('ffi')

local ByteBuffer = {}
local ByteBuffer_mt = { __index = ByteBuffer }

function ByteBuffer.new(buf, len)
	local ptr, maxlen

	if type(buf) == 'string' then
		ptr = ffi.cast('char *', buf)
		maxlen = string.len(buf)
	else
		ptr = buf.ptr
		maxlen = buf.limit - buf.ptr
	end

	len = len or maxlen
	if len > maxlen then
		error('cannot slice beyond end')
	end

	return setmetatable({
		buf = buf,
		ptr = ptr,
		limit = ptr + len,
		frozen = false
	}, ByteBuffer_mt)
end

function ByteBuffer:freeze()
	self.frozen = true
	return self
end

function ByteBuffer:remaining_len()
	return self.limit - self.ptr
end

function ByteBuffer:remaining()
	return ffi.string(self.ptr, self.limit - self.ptr)
end

ByteBuffer_mt.__tostring = ByteBuffer.remaining

function ByteBuffer:read()
	assert(not self.frozen)
	if self.ptr >= self.limit then
		error('reader hit end of buffer')
	end
	local c = self.ptr[0]
	self.ptr = self.ptr + 1
	return c
end

function ByteBuffer:read_int32()
	assert(not self.frozen)
	if self.ptr + 4 > self.limit then
		error('reader hit end of buffer')
	end
	local c = ffi.cast("int32_t *", self.ptr)[0]
	self.ptr = self.ptr + 4
	return c
end

function ByteBuffer:read_int64()
	assert(not self.frozen)
	if self.ptr + 8 > self.limit then
		error('reader hit end of buffer')
	end
	local c = ffi.cast("int64_t *", self.ptr)[0]
	self.ptr = self.ptr + 8
	return c
end

function ByteBuffer:skip(n)
	assert(not self.frozen)
	self.ptr = self.ptr + n
end

return ByteBuffer
