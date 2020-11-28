local _M = {}

local base = require "apisix.plugins.qiyi-waf.wlib.waf.base"

local statistics = ngx.shared.statistics
-- time cost of running whole rule set
local r_time     = "_r_cost"
-- time cost of running waf rule and ct engine
local w_time     = "_w_cost"
-- time cost of running whole lua code
local t_time     = "_t_cost"
-- amount of request
local count      = "_count"

function _M.record(business_name, r_process_time, w_process_time, t_process_time)

	if r_process_time > 0 and w_process_time > 0 and t_process_time > 0 then
		r_incr = statistics:incr(business_name .. r_time, r_process_time, 0)
		w_incr = statistics:incr(business_name .. w_time, w_process_time, 0)
		t_incr = statistics:incr(business_name .. t_time, t_process_time, 0)
		r_count  = statistics:incr(business_name .. count, 1, 0)

		ngx.log(ngx.DEBUG, "TEST INFO : current rule process time : " .. r_incr)
		ngx.log(ngx.DEBUG, "TEST INFO : current rule and ct time : " .. w_incr)
		ngx.log(ngx.DEBUG, "TEST INFO : current total process time : " .. t_incr)
		ngx.log(ngx.DEBUG, "TEST INFO : current request count : " .. r_count)
	end
end

function _M.report(business_name)
	local r_time_amount  = statistics:get(business_name .. r_time)
	local w_time_amount  = statistics:get(business_name .. w_time)
	local t_time_amount  = statistics:get(business_name .. t_time)
	local r_count_amount = statistics:get(business_name .. count)

	local avg_t_time = -1
	local avg_w_time = -1
	local avg_r_time = -1

	if r_time_amount and r_count_amount ~= 0 then
		avg_r_time = r_time_amount / r_count_amount
	end

	if w_time_amount and r_count_amount ~=0 then
		avg_w_time = w_time_amount / r_count_amount
	end

	if t_time_amount and r_count_amount ~=0 then
		avg_t_time = t_time_amount / r_count_amount
	end

	-- clear the storage
	statistics:flush_all()

	ngx.say("*****************Test Report*****************")
	ngx.say(r_count_amount .. " requests are processed.")
	ngx.say("Average Rule Processing Cost is: " .. avg_r_time)
	ngx.say("Average Rule and CT Engine Processing Cost is: " .. avg_w_time)
	ngx.say("Average Total Processing Cost is: " .. avg_t_time)
end

return _M
