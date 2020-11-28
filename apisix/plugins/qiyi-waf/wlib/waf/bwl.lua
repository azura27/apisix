local _M = {}

local base          = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local resty_lock    = require "apisix.plugins.qiyi-waf.wlib.resty.lock"
local cjson         = require "cjson"
local blacklist     = ngx.shared.blacklist

_M.version = base.version

-- provide updating token to nginx work processes
-- due to make sure just one scheduling task does the updating work
function _M.token()
	-- ngx.log(ngx.INFO, "waf-blacklist token")
	local ret = false
	local val, err = blacklist:get("token")

	if not val then
		local lock, err = resty_lock:new("my_locks")
		if lock then
			local elapsed, err = lock:lock("token")
			if elapsed then
				val, err = blacklist:get("token")
				if not val then
					local succ, err = blacklist:set("token", "update token", 60)
					if succ then
						ret = true
					end
				end
				lock:unlock()
			end
		end
	end
	return ret
end

local function match_deser(input, ip_phase, tar_str)
	local tar = cjson.decode(tar_str)

	if tar[ip_phase] then
		if tar[ip_phase]["e"] and tar[ip_phase]["e"] >= input["TS"] then 
			return true, input["IP"]
		end

		if tar[ip_phase]["i"] and tar[ip_phase]["i"][input["URI"]] and tar[ip_phase]["i"][input["URI"]] >= input["TS"] then
			return true, input["URI"]
		end

		if tar[ip_phase]["u"] then
			local ua = input["UA"]
			if tar[ip_phase]["u"][ua] and tar[ip_phase]["u"][ua] >= input["TS"] then
				return true, input["UA"]
			end
		end

		if tar[ip_phase]["uu"] then
			local uu = input["URI"] .. input["UA"]
			if tar[ip_phase]["uu"][uu] and tar[ip_phase]["uu"][uu] >= input["TS"] then
				return true, uu
			end
		end
	end 

	return false
end

function _M.update_deser(buckets)
	-- ngx.log(ngx.INFO, "waf-blacklist update_desi")
	if buckets and type(buckets) == "table" then
		for k, ips in pairs(buckets) do
			local succ, err = blacklist:set(k, cjson.encode(ips))				
			--if succ then
			--	ngx.log(ngx.INFO, "waf-blacklist update success, k:" .. key .. ",expire:" .. tostring(expire))
			--else
			--	ngx.log(ngx.INFO, "waf-blacklist update fail:" .. err)
			--end
		end
	end
end

-- check the input whether in the backilist
function  _M.check(prefix, input)
	if input and type(input) == 'table' then
		-- local index = string.find(input, "%.", 1)
		-- local key = prefix .. "_" .. string.sub(input, 1, index-1)
		local from, to, err  = ngx.re.find(input["IP"], "[0-9]+$", "oij")

		local key = nil
		local ip_phase = nil
		if from then
			key = prefix .. string.sub(input["IP"], from, to)
			ip_phase = string.sub(input["IP"], 1, from-2)
			-- ngx.log(ngx.INFO, "waf-blacklist check key " .. key .. ", val " .. ip_phase)
		else
			-- ngx.log(ngx.WARN, "waf-blacklist check source ip address is invalid")
			return false, nil
		end

		local tar_str, flags = blacklist:get(key)

		if tar_str then
			-- ngx.log(ngx.INFO, "waf-blacklist get ips: " .. tar_str)
			return match_deser(input, ip_phase, tar_str)
		end
	end
	return false, nil
end

return _M
