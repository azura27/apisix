local _M = {}

local base   = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local random = require "apisix.plugins.qiyi-waf.wlib.resty.random"
local string = require "apisix.plugins.qiyi-waf.wlib.resty.string"

_M.version = base.version

function _M.random_bytes(len)
	return string.to_hex(random.bytes(len))
end

return _M
