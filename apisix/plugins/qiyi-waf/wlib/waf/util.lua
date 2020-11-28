local _M = {}

local base   = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local cjson  = require "cjson"
local logger = require "apisix.plugins.qiyi-waf.wlib.waf.log"
local http   = require "apisix.plugins.qiyi-waf.wlib.resty.http"
local time   = require "time"
local redis  = require "apisix.plugins.qiyi-waf.wlib.waf.redis"
local redis_cluster = require "apisix.plugins.qiyi-waf.wlib.waf.rediscluster"

local re_find       = ngx.re.find
local string_byte   = string.byte
local string_char   = string.char
local string_format = string.format
local string_gmatch = string.gmatch
local string_match  = string.match
local string_upper  = string.upper
local table_concat  = table.concat

_M.version = base.version

function _M.get_micro_time()
	return time.getMicroseconds() * 1000000
end

function _M.choose_rulesets(table, table_cow)
	if table._active then
		return table
	elseif table_cow._active then
		return table_cow
	else
		return nil
	end
end

-- fetch initialization data from wafmng
function _M.sync_with_wafmng(config)
	if (type(config) ~= "table") then
		return nil, "config must be a table"
	end

	if(config["sync_target_host"] == nil or config["sync_target_port"] == nil or config["biz_config"] == nil) then
		return nil, "config is not valid"
	end

	local data = cjson.encode(config.biz_config)

	local url = "http://" .. config["sync_target_host"] .. ":" .. config["sync_target_port"] .. "/api/init"
	local cmd = "curl --connect-timeout 3 -m 5 --no-keepalive -d 'biz_config=" .. data .. "' " .. url

--	ngx.log(ngx.INFO,"biz_config is " .. cmd)
	--[[curl --connect-timeout 3 -m 5 --no-keepalive -d 'biz_config={"sys":{"lua":"LuaJIT 2.1.0-beta3","biz":"skywalker","waf":"1.3.2"}}' http://manager.waf.qiyi.domain:80/api/init]]--
	local f = io.popen(cmd)
	local res = f:read("*a")
	f:close()

	if res then
		if res == "" then
			return nil , res
		end

		local jdata, err = _M.parse_ruleset(res)

		if (jdata) then
			return jdata, nil
		else
			return nil, err
		end
	else
		return nil, "sync fail"
	end
end

-- heartbeat via http module
-- can't use it in init phase
function _M.heartbeat_http(config)
	if (type(config) ~= "table") then
                return nil, "config must be a table"
        end

        if (config["sync_target_host"] == nil or config["sync_target_port"] == nil or config["biz_config"] == nil) then
                return nil, "config is not valid"
        end

	local data = cjson.encode(config.biz_config)

	local url = "http://" .. config["sync_target_host"] .. ":" .. config["sync_target_port"] .. "/api/heartbeat"

	local httpc = http.new()
        httpc:set_timeout(3000)
	local res, err = httpc:request_uri(url,{
			method = "POST",
			body = "biz_config=" .. data,
			headers = {
  				["Content-Type"] = "application/x-www-form-urlencoded",
        		}
		})
        local ok = httpc:close()
	
        if res then
		local jdata, err = _M.parse_ruleset(res.body)

		if (jdata) then
			return jdata, nil
		else
			return nil, err
		end
	else
		return nil, err
	end
end

-- duplicate a table using recursion if necessary for multi-dimensional tables
-- useful for getting a local copy of a table
function _M.table_copy(orig)
	local orig_type = type(orig)
	local copy

	if orig_type == 'table' then
		copy = {}

		for orig_key, orig_value in next, orig, nil do
			copy[_M.table_copy(orig_key)] = _M.table_copy(orig_value)
		end

		setmetatable(copy, _M.table_copy(getmetatable(orig)))
	else
		copy = orig
	end
	return copy
end

-- return a table containing the keys of the provided table
function _M.table_keys(table)
	if (type(table) ~= "table") then
		logger.fatal_fail(type(table) .. " was given to table_keys!")
	end

	local t = {}
	local n = 0

	for key, _ in pairs(table) do
		n = n + 1
		t[n] = tostring(key)
	end

	return t
end

-- return a table containing the values of the provided table
function _M.table_values(table)
	if (type(table) ~= "table") then
		logger.fatal_fail(type(table) .. " was given to table_values!")
	end

	local t = {}
	local n = 0

	for _, value in pairs(table) do
		-- if a table as a table of values, we need to break them out and add them individually
		-- request_url_args is an example of this, e.g. ?foo=bar&foo=bar2
		if (type(value) == "table") then
			for _, values in pairs(value) do
				n = n + 1
				t[n] = tostring(values)
			end
		else
			n = n + 1
			t[n] = tostring(value)
		end
	end

	return t
end

-- return true if the table key exists
function _M.table_has_key(needle, haystack)
	if (type(haystack) ~= "table") then
		logger.fatal_fail("Cannot search for a needle when haystack is type " .. type(haystack))
	end

	return haystack[needle] ~= nil
end

-- determine if the haystack table has a needle for a key
function _M.table_has_value(needle, haystack)
	if (type(haystack) ~= "table") then
		logger.fatal_fail("Cannot search for a needle when haystack is type " .. type(haystack))
	end

	for _, value in pairs(haystack) do
		if (value == needle) then
			return true
		end
	end

	return false
end

function _M.table_append(a, b)
	-- handle some ugliness
	local c = type(b) == 'table' and b or { b }

	local a_count = #a

	for i = 1, #c do
		a_count = a_count + 1
		a[a_acount] = c[i]
	end
end

-- pick out dynamic data from storage key definitions
function _M.parse_dynamic_value(waf, key, collections)
	local lookup = function(m)
		local val      = collections[string_upper(m[1])]
		local specific = m[2]

		if not val then
			logger.fatal_fail("Bad dynamic parse, no collection key " .. m[1])
		end

		if type(val) == "table" then
			if specific then
				return tostring(val[specific])
			else
				return m[1]
			end
		else
			return val
		end
	end

	-- grab something that looks like
	-- %{VAL} or %{VAL.foo}
	-- and find it in the lookup table
	local str = ngx.re.gsub(key, [[%{([A-Za-z_]+)(?:\.([^}]+))?}]], lookup, waf._pcre_flags)

	--_LOG_"Parsed dynamic value is " .. str

	if ngx.re.find(str, [=[^\d+$]=], waf._pcre_flags) then
		return tonumber(str)
	else
		return str
	end
end

-- safely attempt to parse a JSON string as a ruleset
function _M.parse_ruleset(data)
	local jdata

	if pcall(function() jdata = cjson.decode(data) end) then
		return jdata, nil
	else
		return nil, "could not decode " .. data
	end
end

-- find a rule file with a .json prefix, read it, and return a JSON string
function _M.load_ruleset_file(name)
	for k, v in string_gmatch(package.path, "[^;]+") do
		local path = string_match(k, "(.*/)")

		local full_name = path .. "rules/" .. name .. ".json"

		local f = io.open(full_name)
		if f ~= nil then
			local data = f:read("*all")

			f:close()

			return _M.parse_ruleset(data)
		end
	end

	return nil, "could not find " .. name
end

-- encode a given string as hex
function _M.hex_encode(str)
	return (str:gsub('.', function (c)
		return string_format('%02x', string_byte(c))
	end))
end

-- decode a given hex string
function _M.hex_decode(str)
	local value

	if (pcall(function()
		value = str:gsub('..', function (cc)
			return string_char(tonumber(cc, 16))
		end)
	end)) then
		return value
	else
		return str
	end
end

-- build an RBLDNS query by reversing the octets of an IPv4 address and prepending that to the rbl server name
function _M.build_rbl_query(ip, rbl_srv)
	if (type(ip) ~= 'string') then
		return false
	end

	local o1, o2, o3, o4 = ip:match("(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)")

	if not o1 and not o2 and not o3 and not o4 then
		return false
	end

	local t = { o4, o3, o2, o1, rbl_srv }

	return table_concat(t, '.')
end

-- parse collection elements based on a given directive
_M.parse_collection = {
	specific = function(waf, collection, value)
		--_LOG_"Parse collection is getting a specific value: " .. value
		return collection[value]
	end,
	regex = function(waf, collection, value)
		local v
		local n = 0
		local _collection = {}
		for k, _ in pairs(collection) do
			if ngx.re.find(k, value, waf._pcre_flags) then
				v = collection[k]
				if (type(v) == "table") then
					for __, _v in pairs(v) do
						n = n + 1
						_collection[n] = _v
					end
				else
					n = n + 1
					_collection[n] = v
				end
			end
		end
		return _collection
	end,
	ignore_regex = function(waf, collection, value)
		local v
		local n = 0
		local _collection = {}
		for k, _ in pairs(collection) do
			if (not ngx.re.find(k, value, waf._pcre_flags)) then
				v = collection[k]
				if (type(v) == "table") then
					for __, _v in pairs(v) do
						n = n + 1
						_collection[n] = _v
					end
				else
					n = n + 1
					_collection[n] = v
				end
			end
		end
		return _collection
	end,
	ignore = function(waf, collection, value)
		logger.log(waf, "Parse collection is ignoring a value: " .. value)
		local _collection = {}
		_collection = _M.table_copy(collection)
		_collection[value] = nil
		return _collection
	end,
	keys = function(waf, collection)
		--_LOG_"Parse collection is getting the keys"
		return _M.table_keys(collection)
	end,
	values = function(waf, collection)
		--_LOG_waf, "Parse collection is getting the values"
		return _M.table_values(collection)
	end,
	all = function(waf, collection)
		local n = 0
		local _collection = {}
		for _, key in ipairs(_M.table_keys(collection)) do
			n = n + 1
			_collection[n] = key
		end
		for _, value in ipairs(_M.table_values(collection)) do
			n = n + 1
			_collection[n] = value
		end
		return _collection
	end
}


_M.sieve_collection = {
	ignore = function(waf, collection, value)
		--_LOG_"Sieveing specific value " .. value
		collection[value] = nil
	end,
	regex = function(waf, collection, value)
		--_LOG_"Sieveing regex value " .. value
		for k, _ in pairs(collection) do
			--_LOG_"Checking " .. k
			if ngx.re.find(k, value, waf._pcre_flags) then
				--_LOG_"Removing " .. k
				collection[k] = nil
			end
		end
	end,
}

-- build the msg/tag exception table for a given rule
function _M.rule_exception(exception_table, rule)
	if not rule.exceptions then
		return
	end

	local ids   = {}
	local count = 0

	for i, exception in ipairs(rule.exceptions) do
		for key, rules in pairs(exception_table.msgs) do
			if re_find(key, exception, 'jo') then
				for j, id in ipairs(rules) do
					count = count + 1
					ids[count] = id
				end
			end
		end

		for key, rules in pairs(exception_table.tags) do
			if re_find(key, exception, 'jo') then
				for j, id in ipairs(rules) do
					count = count + 1
					ids[count] = id
				end
			end
		end
	end

	if count > 0 then
		exception_table.meta_ids[rule.id] = ids
	end
end

-- split string
function _M.string_split(str, split_char)
    local sub_str_tab = {};
    while (true) do
        local pos = string.find(str, split_char);
        if (not pos) then
            sub_str_tab[#sub_str_tab + 1] = str;
            break;
        end
        local sub_str = string.sub(str, 1, pos - 1);
        sub_str_tab[#sub_str_tab + 1] = sub_str;
        str = string.sub(str, pos + 1, #str);
    end
 
    return sub_str_tab;
end

function _M.check_access_limit_rate(red, rule, ctx)
	local jdata = cjson.decode(rule)
	local current_time = ngx.time()
	local _user_keys = {}
	local user_keys = {}
	for _, v in pairs(jdata.match_method.target_type) do
		if v['key'] == 'IP' then
			if v['value'] == 'CLIENT_IP' then
				_user_keys = {ctx.collections.CLIENT_IP}
			elseif v['value'] == 'REMOTE_ADDR' then
				_user_keys = {ctx.collections.REMOTE_ADDR}
			end
		elseif v['key'] == 'HEADER' then
			local hv = ctx.collections.REQUEST_HEADERS[v['value']]
			if hv then
				if (type(hv) ~= "table") then
					_user_keys = {hv}
				else
					_user_keys = hv
				end
			end
		elseif v['key'] == 'GET' then
			local gv = ctx.collections.URI_ARGS[v['value']]
			if gv then
				if (type(gv) ~= "table") then
					_user_keys = {gv}
				else
					_user_keys = gv
				end
			end
		elseif v['key'] == 'POST' then
			if ctx.collections.REQUEST_BODY then
				local pv = ctx.collections.REQUEST_BODY[v['value']]
				if pv then
					if (type(pv) ~= "table") then
						_user_keys = {pv}
					else
						_user_keys = pv
					end
				end
			end
		elseif v['key'] == 'COOKIE' then
			local cv = ctx.collections.COOKIES[v['value']]
			if cv then
				if (type(cv) ~= "table") then
					_user_keys = {cv}
				else
					_user_keys = cv
				end
			end
		end

		if #user_keys == 0 then
			for _k, _v in pairs(_user_keys) do
				if type(_v) == 'string' then
					user_keys[#user_keys + 1] = _v
				end
			end
		else
			local tmp_user_keys = {}
			for _k, _v in pairs(user_keys) do
				for __k, __v in pairs(_user_keys) do
					if type(__v) == 'string' then
						tmp_user_keys[#tmp_user_keys + 1] = _v .. __v
					end
				end
			end
			if #tmp_user_keys ~= 0 then
				user_keys = tmp_user_keys
			end
		end
		_user_keys = {}
	end

	for _, user_key in pairs(user_keys) do
		if user_key ~= '' then
			--logger.err_log(user_key)
			local black_key = 'black:rule_' .. jdata.id .. ':' .. ngx.md5(user_key)
			local resp, err = red:get(black_key)
			if resp == "1" then
				if jdata.action.action == "forbid" then
					return 'DENY'
				elseif jdata.action.action == "verify" then
					return 'VERIFY'
				elseif jdata.action.action == "Limit Rate" then
					local limit_rate_period = jdata.action.limit_rate_period -- 限流时间范围
					local limit_rate_limit = jdata.action.limit_rate_limit -- 限流次数
					local limit_key = 'limit_rate:rule_' .. jdata.id .. ':' .. ngx.md5(user_key)
					local res, err = red:eval([[
						local limitlen = redis.call('LLEN', KEYS[1])
						if limitlen < tonumber(ARGV[1]) then
							redis.call('LPUSH', KEYS[1], ARGV[2])
							redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]) + 5)
						else
							local time = redis.call('LINDEX', KEYS[1], -1)
							redis.call('LPUSH', KEYS[1], ARGV[2])
							redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]) + 5)
							redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[1])-1)
							if tonumber(ARGV[2]) - tonumber(time) < tonumber(ARGV[3]) then
								return 'DENY'
							end
						end
					]], 1, limit_key, limit_rate_limit, current_time, limit_rate_period)
					if res == 'DENY' then
						return 'DENY'
					end
				end
			else
				if jdata.is_match_method then
					local expire_period = jdata.expire_period -- 限制时间
					local period = jdata.match_method.period -- 触发时间范围
					local limit = jdata.match_method.limit -- 触发次数
					local limit_key = 'match_limit:rule_' .. jdata.id .. ':' .. ngx.md5(user_key)
					local black_key = 'black:rule_' .. jdata.id .. ':' .. ngx.md5(user_key)
					local res, err = red:eval([[
						local limitlen = redis.call('LLEN', KEYS[1])
						if limitlen < tonumber(ARGV[1]) then
							redis.call('LPUSH', KEYS[1], ARGV[2])
							redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]) + 5)
						else
							local time = redis.call('LINDEX', KEYS[1], -1)
							redis.call('LPUSH', KEYS[1], ARGV[2])
							redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]) + 5)
							redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[1])-1)
							return time
						end
					]], 1, limit_key, limit, current_time, period)
					if res then
						local res, err = red:eval([[
							if tonumber(ARGV[2]) - tonumber(ARGV[1]) < tonumber(ARGV[3]) then
								redis.call('SET', KEYS[1], '1')
								redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
							end
						]], 1, black_key, res, current_time, period, expire_period)
					end
				end
			end
		end
	end
end

function _M.access_limit_rate(rule, ctx)
	local count = ngx.worker.count()
	local config = {
		name = "waf_limit",
		serv_list = {
			{ ip = "10.62.57.89", port = 7319 },
			{ ip = "10.62.57.28", port = 7319 },
			{ ip = "10.62.59.59", port = 7319 },
			{ ip = "10.62.59.55", port = 7319 },
			{ ip = "10.62.59.62", port = 7319 },
			{ ip = "10.62.59.64", port = 7319 }
		},
		keepalive_timeout = 60000,              --redis connection pool idle timeout
		keepalive_cons = math.ceil(100/count),  --redis connection pool size
		connection_timout = 1000,               --timeout while connecting
		max_redirection = 5,                    --maximum retry attempts for redirection
		max_connection_attempts = 1,            --maximum retry attempts for connection
		auth = "Ou5IW4o5Bt3a"                   --set password while setting auth
	}
	local red = redis_cluster:new(config)

	local action = _M.check_access_limit_rate(red, rule, ctx)

	return action
end

function _M._check_bwlist(red, rule, ctx)
	local jdata = cjson.decode(rule)
	local _user_keys = {}
	local user_keys = {}
	for _, v in pairs(jdata.target_type) do
		if v['key'] == 'IP' then
			if v['value'] == 'CLIENT_IP' then
				_user_keys = {ctx.collections.CLIENT_IP}
			elseif v['value'] == 'REMOTE_ADDR' then
				_user_keys = {ctx.collections.REMOTE_ADDR}
			end
		elseif v['key'] == 'HEADER' then
			local hv = ctx.collections.REQUEST_HEADERS[v['value']]
			if hv then
				if (type(hv) ~= "table") then
					_user_keys = {hv}
				else
					_user_keys = hv
				end
			end
		elseif v['key'] == 'GET' then
			local gv = ctx.collections.URI_ARGS[v['value']]
			if gv then
				if (type(gv) ~= "table") then
					_user_keys = {gv}
				else
					_user_keys = gv
				end
			end
		elseif v['key'] == 'POST' then
			if ctx.collections.REQUEST_BODY then
				local pv = ctx.collections.REQUEST_BODY[v['value']]
				if pv then
					if (type(pv) ~= "table") then
						_user_keys = {pv}
					else
						_user_keys = pv
					end
				end
			end
		elseif v['key'] == 'COOKIE' then
			local cv = ctx.collections.COOKIES[v['value']]
			if cv then
				if (type(cv) ~= "table") then
					_user_keys = {cv}
				else
					_user_keys = cv
				end
			end
		end

		if #user_keys == 0 then
			for _k, _v in pairs(_user_keys) do
				if type(_v) == 'string' then
					user_keys[#user_keys + 1] = _v
				end
			end
		else
			local tmp_user_keys = {}
			for _k, _v in pairs(user_keys) do
				for __k, __v in pairs(_user_keys) do
					if type(__v) == 'string' then
						tmp_user_keys[#tmp_user_keys + 1] = _v .. __v
					end
				end
			end
			if #tmp_user_keys ~= 0 then
				user_keys = tmp_user_keys
			end
		end
		_user_keys = {}
	end

	for _, user_key in pairs(user_keys) do
		if user_key ~= '' then
			--logger.err_log(user_key)
			local black_key = 'black_list:rule_' .. jdata.id .. ':' .. ngx.md5(user_key)
			local resp, err = red:get(black_key)
			if resp == "1" then
				if jdata.action == "forbid" then
					return 'DENY'
				elseif jdata.action == "verify" then
					return 'VERIFY'
				end
			end
		end
	end
end

function _M.check_bwlist(rule, ctx)
	local red = redis:new()
	red:set_timeout(500) -- 0.5 sec

	-- 连接
	local ok, err = red:connect("bjzyx.wafbwlist.r.qiyi.redis", 6485)
	if not ok then
		--写错误日志
		return
	end

	-- 鉴权
	local count, err = red:get_reused_times()
	if 0 == count then
		local ok, err = red:auth("7IbO8tPiFn98")
		if not ok then
			--写错误日志
			return
		end
	elseif err then
		--写错误日志
		return
	end

	local action = _M._check_bwlist(red, rule, ctx)

	-- 连接池
	local count = ngx.worker.count()
	local ok, err = red:set_keepalive(60000, math.ceil(100/count))
	if not ok then
		--写错误日志
		return
	end

	return action
end

return _M
