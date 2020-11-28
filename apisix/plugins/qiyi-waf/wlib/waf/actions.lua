local _M = {}

local base    = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local logger  = require "apisix.plugins.qiyi-waf.wlib.waf.log"
local storage = require "apisix.plugins.qiyi-waf.wlib.waf.storage"
local util    = require "apisix.plugins.qiyi-waf.wlib.waf.util"
local aes 		 = require "apisix.plugins.qiyi-waf.wlib.resty.core.aes"
local cjson   = require "cjson"

_M.version = base.version

_M.alter_actions = {
	DENY     = true,
	DROP     = true,
	ACCEPT   = true,
	VERIFY   = true,
	VERIFYCACHE = true,
	ALERT    = true,
}

local function _encrypt(str)
	-- AES 128 CBC with IV and no SALT
	local aes_128_cbc_with_iv = assert(aes:new("g7s2xs4p5i007j65", nil, aes.cipher(128,"cbc"), {iv="qwertyuiopasdfgh"}))
	local encrypted = aes_128_cbc_with_iv:encrypt(str)
	local encrypted_hex = util.hex_encode(encrypted)
	return encrypted_hex
end

local function _decrypt(str)
	-- AES 128 CBC with IV and no SALT
	local aes_128_cbc_with_iv = assert(aes:new("g7s2xs4p5i007j65", nil, aes.cipher(128,"cbc"), {iv="qwertyuiopasdfgh"}))
	local decrypted = aes_128_cbc_with_iv:decrypt(util.hex_decode(str))
	return decrypted
end

-- set cookie for authenticate center
local function _set_cookie_for_authenticate_center(ctx)
	--Extract essential data
	local headers = ctx.collections["REQUEST_HEADERS"]
	local ip = ctx.collections["REMOTE_ADDR"]
	local host = headers["host"]
	local uri = ctx.collections["URI"]
	local ua_md5 = ngx.md5(headers["user-agent"])
	local timestamp = os.time()
	local str = ip .. "|" .. host .. "|" .. uri .. "|" .. ua_md5 .. "|" .. timestamp

	local encrypted = _encrypt(str)

	--Set cookie for verify center
	local vc_bizname = "waf"
	local cookies = ngx.header["Set-Cookie"] or {}
	if type(cookies) == "string" then
		cookies = {cookies}
	end
	local expires = 3600 * 0.5  -- 0.5h day
	local domain = host:match("[%w%.]*%.(%w+%.%w+)")
	local cookie = "_VCR_=" .. vc_bizname .. "|" .. encrypted .. "; Domain=" .. domain .. "; Path=/; Expires=" .. ngx.cookie_time(ngx.time() + expires)
	table.insert(cookies, cookie)
	ngx.header['Set-Cookie'] = cookies
end

--redirect request to verify center
local function _redirect_to_verifycenter(ctx, is_cache, ...)
	local verify_page = ""
	if string.find(ctx.collections["REQUEST_HEADERS"]["host"], 'qiyi.domain', 1, true) then
		verify_page = "http://security.qiyi.domain/static/v2/verifycenter/page/wft.html"
	else
		verify_page = "http://security.iqiyi.com/static/v2/verifycenter/page/wft.html"
	end
	local port = ngx.var.server_port
	local protocol_header = ngx.var.scheme .. '://'
	local origin_request = protocol_header .. ctx.collections["REQUEST_HEADERS"]["host"] .. ctx.collections["REQUEST_URI_RAW"]

	if is_cache then
	  local appender = tostring(ngx.time())
	  local uriraw = ctx.collections["REQUEST_URI_RAW"]
		if uriraw and string.match(uriraw, "?") then
			appender = "&msjkgc=" .. appender
		else
			appender = "?msjkgc=" .. appender
		end
    origin_request = origin_request .. appender
  end
	local verify_endpoint = verify_page .. "?redirectUrl=" .. origin_request
	if ctx.qiyi_mode == "ACTIVE" then
		ctx.action = "REDIRECT_VERIFY"
		if ... == 'RATE_VERIFY' or ... == 'BW_VERIFY' then
			ctx.action = ...
		end
		--add cookie for verify center
		_set_cookie_for_authenticate_center(ctx)
		ngx.redirect(verify_endpoint, 302)
	end
end

local function _verify(ctx, is_cache, ...)
	--store cookie in table
	local cookies = ctx.collections["COOKIES"] or {}
	if type(cookies) == "string" then
		cookies = {cookies}
	end

	--get the cookie key from verifycenter
	local host = ctx.collections["REQUEST_HEADERS"]["host"]
	local domain = host:match("[%w%.]*%.(%w+%.%w+)")
	local i, j = string.find(host, domain)
	local cookie_key = "_VC_" .. string.sub(host,0,i-2)

	if cookies[cookie_key] then
		--verify the cookie, if cookie is verified, pass; else redirect to verifycenter
		local encrypted_result = cookies[cookie_key]
		local decryptedstr = _decrypt(encrypted_result)
		--assemble str from request
		local headers = ctx.collections["REQUEST_HEADERS"]
		local ip = ctx.collections["REMOTE_ADDR"]
		local host = headers["host"]
		local uri = ctx.collections["URI"]
		local ua_md5 = ngx.md5(headers["user-agent"])
		local assembledstr = ip .. "|" .. host .. "|" .. uri .. "|" .. ua_md5
		if type(decryptedstr) == 'string' and string.find(decryptedstr, assembledstr, 1, true) and string.len(assembledstr) + 44 == string.len(decryptedstr) then
			local timestamp_vc = tonumber(string.sub(decryptedstr, string.len(assembledstr)+2, string.len(decryptedstr)-33))
			local localtime = ngx.time()
			if timestamp_vc > localtime or localtime-timestamp_vc > 600 then
				_redirect_to_verifycenter(ctx, is_cache, ...)
			else
				ngx.exit(ngx.OK)
			end
		else
			_redirect_to_verifycenter(ctx, is_cache, ...)
		end
	else
		--If not exist cookie from verify center, redirect to verify center
		_redirect_to_verifycenter(ctx, is_cache, ...)
	end
end

_M.disruptive_lookup = {
	ALERT = function(waf, ctx)
		--命中alert的请求，不会转发到长亭引擎去过滤，直接予以放行，只在日志之中做出记录
		if ctx.ct_mode ~= "INACTIVE" then
			ctx.bypass_changting = true
		end
		ctx.action = "ALERT"
		ngx.exit(ngx.OK)
	end,
	VERIFY = function(waf, ctx, ...)
		_verify(ctx, false, ...)
	end,
	VERIFYCACHE = function(waf, ctx)
		_verify(ctx, true)
	end,
	ACCEPT = function(waf, ctx)
		--_LOG_"Rule action was ACCEPT, so ending this phase with ngx.OK"
		if ctx.ct_mode ~= "INACTIVE" then
			ctx.bypass_changting = true
		end

		if ctx.qiyi_mode == "ACTIVE" then
			ctx.action = "Q_ACCEPT"
			ngx.exit(ngx.OK)
		end
	end,
	CHAIN = function(waf, ctx)
		--_LOG_"Chaining (pre-processed)"
	end,
	DENY = function(waf, ctx)
		if ctx.ct_mode ~= "INACTIVE" then
			ctx.bypass_changting = true
		end

		--_LOG_"Rule action was DENY, so telling nginx to quit"
		if ctx.qiyi_mode == "ACTIVE" then
			ctx.action = "Q_DENY"
			ngx.exit(ctx.rule_status or waf._deny_status)
			-- deny(waf, ctx)
		end
	end,
	IGNORE = function(waf)
		--_LOG_"Ignoring rule for now"
	end,
	SCORE = function(waf, ctx)
		--_LOG_"Score isn't a thing anymore, see TX.anomaly_score"
	end,
}

_M.nondisruptive_lookup = {
	deletevar = function(waf, data, ctx, collections)
		storage.delete_var(waf, ctx, data)
	end,
	expirevar = function(waf, data, ctx, collections)
		local time = util.parse_dynamic_value(waf, data.time, collections)

		storage.expire_var(waf, ctx, data, time)
	end,
	initcol = function(waf, data, ctx, collections)
		local col    = data.col
		local value  = data.value
		local parsed = util.parse_dynamic_value(waf, value, collections)

		--_LOG_"Initializing " .. col .. " as " .. parsed

		storage.initialize(waf, ctx.storage, parsed)
		ctx.col_lookup[col] = parsed
		collections[col]    = ctx.storage[parsed]
	end,
	setvar = function(waf, data, ctx, collections)
		data.key    = util.parse_dynamic_value(waf, data.key, collections)
		local value = util.parse_dynamic_value(waf, data.value, collections)

		storage.set_var(waf, ctx, data, value)
	end,
	sleep = function(waf, time)
		--_LOG_"Sleeping for " .. time

		ngx.sleep(time)
	end,
	status = function(waf, status, ctx)
		--_LOG_"Overriding status from " .. waf._deny_status .. " to " .. status

		ctx.rule_status = status
	end,
	rule_remove_id = function(waf, rule)
		--_LOG_"Runtime ignoring rule " .. rule

		waf._ignore_rule[rule] = true
	end,
	rule_remove_by_meta = function(waf, data, ctx)
		--_LOG_"Runtime ignoring rules by meta"

		-- this lookup table holds
		local meta_rules = waf._meta_exception.meta_ids[ctx.id] or {}

		for i, id in ipairs(meta_rules) do
			--_LOG_"Runtime ignoring rule " .. id
			waf._ignore_rule[id] = true
		end
	end,
	skip_changting = function(waf, ctx)
		if ngx.req.get_headers()["X-APISIX-CT-WAF-Switch"] then
			ngx.req.clear_header("X-APISIX-CT-WAF-Switch")
		end
	end
}

return _M
