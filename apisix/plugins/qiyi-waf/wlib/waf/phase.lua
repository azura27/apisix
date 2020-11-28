local _M = {}

local base = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local util = require "apisix.plugins.qiyi-waf.wlib.waf.util"

_M.version = base.version

_M.phases = { rewrite = 1, header_filter = 2, body_filter = 3, log = 4 }

function _M.is_valid_phase(phase)
	return util.table_has_key(phase, _M.phases)
end

return _M
