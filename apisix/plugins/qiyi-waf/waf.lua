local _M = {}

local actions       = require "apisix.plugins.qiyi-waf.wlib.waf.actions"
local base          = require "apisix.plugins.qiyi-waf.wlib.waf.base"
local calc          = require "apisix.plugins.qiyi-waf.wlib.waf.rule_calc"
local collections_t = require "apisix.plugins.qiyi-waf.wlib.waf.collections"
local logger        = require "apisix.plugins.qiyi-waf.wlib.waf.log"
local operators     = require "apisix.plugins.qiyi-waf.wlib.waf.operators"
local options       = require "apisix.plugins.qiyi-waf.wlib.waf.options"
local opts          = require "apisix.plugins.qiyi-waf.wlib.waf.opts"
local phase_t       = require "apisix.plugins.qiyi-waf.wlib.waf.phase"
local random        = require "apisix.plugins.qiyi-waf.wlib.waf.random"
local storage       = require "apisix.plugins.qiyi-waf.wlib.waf.storage"
local transform_t   = require "apisix.plugins.qiyi-waf.wlib.waf.transform"
local translate     = require "apisix.plugins.qiyi-waf.wlib.waf.translate"
local util          = require "apisix.plugins.qiyi-waf.wlib.waf.util"
local bwl           = require "apisix.plugins.qiyi-waf.wlib.waf.bwl"
local cjson         = require "cjson"
local core          = require("apisix.core")
--local benchmark   = require "wlib.waf.benchmark"

local _INACTIVE = "INACTIVE"

local table_sort   = table.sort
local string_lower = string.lower

local ok, tab_new = pcall(require, "table.new")
if not ok then
	tab_new = function(narr, nrec) return {} end
end

local mt = { __index = _M }

_M.version = base.version

-- default list of rulesets
local _global_rulesets = {
	"12000_custom",
	"13000_system",
	"14000_sqli",
	"15000_xss",
	"99000_scoring"
}

_M.global_rulesets = _global_rulesets

-- ruleset table cache
local _ruleset_defs     = {_active = false}
local _ruleset_defs_cow = {_active = false}
local _ruleset_cache    = {}

-- default options
local default_opts = util.table_copy(opts.defaults)

local _biz_config = {}
local _domainbizmap = {}

_M._meta_exception = {
	msgs = {},
	tags = {},
	meta_ids = {},
}

-- get a subset or superset of request data collection
local function _parse_collection(self, collection, var)
	local parse = var.parse

	if type(collection) ~= "table" and parse then
		-- if a collection isn't a table it can't be parsed,
		-- so we shouldn't return the original collection as
		-- it may have an illegal operator called on it
		return nil
	end

	-- if type(collection) ~= "table" or not parse then
	if not parse then
		-- this collection isnt parseable but it's not unsafe to use
		return collection
	end

	local key   = parse[1]
	local value = parse[2]

	-- if this var has an ignore, we need to copy this collection table
	-- as we're going to be removing some of its elements, so we can no
	-- longer use it simply as a reference
	if var.ignore then
		local collection_copy = util.table_copy(collection)

		for _, ignore in ipairs(var.ignore) do
			local ikey   = ignore[1]
			local ivalue = ignore[2]

			util.sieve_collection[ikey](self, collection_copy, ivalue)
		end

		return util.parse_collection[key](self, collection_copy, value)
	end

	-- since we didn't have to ignore, we can just parse the collection
	-- based on the parse key (specific, keys, values, etc)
	return util.parse_collection[key](self, collection, value)
end

-- buffer a single log event into the per-request ctx table
-- all event logs will be written out at the completion of the transaction if either:
-- 1. the transaction was altered (e.g. a rule matched with an ACCEPT or DENY action), or
-- 2. the event_log_altered_only option is unset
local function _log_event(self, rule, value, ctx)
	local t = {
		rule_id = rule.id,
		match   = value,
		action  = rule.actions.disrupt
	}

	if rule.attack_type and rule.attack_level then
		ctx.attack_type  = rule.attack_type
		ctx.attack_level = rule.attack_level
	end

	if rule.msg then
		t.msg = util.parse_dynamic_value(self, rule.msg, ctx.collections)
	end

	if rule.logdata then
		t.logdata = util.parse_dynamic_value(self, rule.logdata, ctx.collections)
	end

	ctx.log_entries_n = ctx.log_entries_n + 1
	ctx.log_entries[ctx.log_entries_n] = t
end

-- restore options from a previous phase
local function _load(self, opts)
	for k, v in pairs(opts) do
		self[k] = v
	end
end

-- save options to the ctx table to be used in another phase
local function _save(self, ctx)
	local opts = {}

	for k, v in pairs(self) do
		opts[k] = v
	end

	ctx.opts = opts
end

local function _transaction_id_header(self, ctx)
	-- upstream request header
	if (self._req_tid_header) then
		ngx.req.set_header("X-Lua-Resty-WAF-ID", self.transaction_id)
	end

	-- downstream response header
	if (self._res_tid_header) then
		ngx.header["X-Lua-Resty-WAF-ID"] = self.transaction_id
	end

	ctx.t_header_set = true
end

-- cleanup
local function _finalize(self, ctx)
	-- set X-Lua-Resty-WAF-ID headers as appropriate
	if (not ctx.t_header_set) then
		_transaction_id_header(self, ctx)
	end

	-- save our options for the next phase
	ctx.opts = self

	-- persistent variable storage
	storage.persist(self, ctx.storage)

	-- record the elapsed time of processing a request
	local r_finish = util.get_micro_time()

	if r_finish >= ctx.start then
		ctx.r_process_time = r_finish - ctx.start
	end

	-- store the local copy of the ctx table
	ngx.ctx.lua_resty_waf = ctx

	if ctx.phase == 'log' then
		self:write_log_events(true, ctx)
	end
end

-- use the lookup table to figure out what to do
local function _rule_action(self, action, ctx, collections)
  if not action then
		return
	end

	if util.table_has_key(action, actions.alter_actions) then
		ctx.altered = true
		_finalize(self, ctx)
	end

	if self._hook_actions[action] then
		self._hook_actions[action](self, ctx)
	else
		actions.disruptive_lookup[action](self, ctx)
	end
end

-- transform collection values based on rule opts
local function _do_transform(self, collection, transform)
	local t = {}

	if type(transform) == "table" then
		t = collection

		for k, v in ipairs(transform) do
			t = _do_transform(self, t, transform[k])
		end
	else
		-- if the collection is a table, loop through it and add the values to the tmp table
		-- otherwise, this returns directly to _process_rule or a recursed call from multiple transforms
		if (type(collection) == "table") then
			for k, v in pairs(collection) do
				t[k] = _do_transform(self, collection[k], transform)
			end
		else
			if (not collection) then
				return collection -- dont transform if the collection was nil, i.e. a specific arg key dne
			end

			--_LOG_"doing transform of type " .. transform .. " on collection value " .. tostring(collection)
			return transform_t.lookup[transform](self, collection)
		end
	end

	return t
end

-- process an individual rule
local function _process_rule(self, rule, collections, ctx)
	local id       = rule.id
	local vars     = rule.vars
	local opts     = rule.opts or {}
	local pattern  = rule.pattern
	local operator = rule.operator
	local offset

	ctx.id = id

	ctx.rule_status = nil

	for k, v in ipairs(vars) do
		local collection, var
		var = vars[k]

		if var.unconditional then
			collection = true
		else
			local collection_key = var.collection_key
			--_LOG_"Checking for collection_key " .. collection_key

			if not var.storage and not ctx.transform_key[collection_key] then
				--_LOG_"Collection cache miss"
				collection = _parse_collection(self, collections[var.type], var)

				if (opts.transform) then
					collection = _do_transform(self, collection, opts.transform)
				end

				ctx.transform[collection_key]     = collection
				ctx.transform_key[collection_key] = true
			elseif var.storage then
				--_LOG_"Forcing cache miss"
				collection = _parse_collection(self, collections[var.type], var)
			else
				--_LOG_"Collection cache hit!"
				collection = ctx.transform[collection_key]
			end

			if var.length then
				if type(collection) == 'table' then
					collection = #collection
				elseif(collection) then
					collection = 1
				else
					collection = 0
				end
			end
		end

		if not collection then
			--_LOG_"No values for this collection"
			offset = rule.offset_nomatch
		else
			if opts.parsepattern then
				--_LOG_"Parsing dynamic pattern: " .. pattern
				pattern = util.parse_dynamic_value(self, pattern, collections)
			end

			local match, value

			if var.unconditional then
				match = true
				value = 1
			else
				match, value = operators.lookup[operator](self, collection, pattern, ctx)
			end

			if rule.op_negated then
				match = not match
			end

			if match then
				--_LOG_"Match of rule " .. id

				-- store this match as the most recent match
				collections.MATCHED_VAR      = value
				collections.MATCHED_VAR_NAME = var

				-- also add the match to our list of matches for the transaction
				if value then
					local match_n = ctx.match_n + 1
					collections.MATCHED_VARS[match_n] = valueg
					collections.MATCHED_VAR_NAMES[match_n] = var
					ctx.match_n = match_n
				end

				-- auto populate collection elements
				if not rule.op_negated then
					if operator == "REGEX" then
						collections.TX["0"] = value[0]
						for i in ipairs(value) do
							collections.TX[tostring(i)] = value[i]
						end
					else
						collections.TX["0"] = value
					end
				end
				collections.RULE = rule

				local nondisrupt = rule.actions.nondisrupt or {}
				for _, action in ipairs(nondisrupt) do
					actions.nondisruptive_lookup[action.action](self, action.data, ctx, collections)
				end

				-- log the event
				if rule.actions.disrupt ~= "CHAIN" and not opts.nolog then
					_log_event(self, rule, value, ctx)
				end

				-- wrapper for the rules action
				_rule_action(self, rule.actions.disrupt, ctx, collections)

				offset = rule.offset_match

				break
			else
				offset = rule.offset_nomatch
			end
		end
	end

	--_LOG_"Returning offset " .. tostring(offset)
	return offset
end

-- calculate rule jump offsets
local function _calculate_offset(ruleset)
	for phase, i in pairs(phase_t.phases) do
		if ruleset[phase] then
			calc.calculate(ruleset[phase], _M.meta_exception)
		else
			ruleset[phase] = {}
		end
	end
	--ruleset.initted = true
end

-- merge the default and any custom rules
local function _merge_rulesets(self)
	local default = _global_rulesets
	local t = {}

	for k, v in ipairs(default) do
		t[v] = true
	end

	t = util.table_keys(t)

	-- rulesets will be processed in numeric order
	table_sort(t, function(a, b)
		return string_lower(a) < string_lower(b)
	end)

	self._active_rulesets = t
end

-- scheduling heartbeat
function _M.scheduling_heartbeat()
	local delay = default_opts._sync_delay
	local new_timer = ngx.timer.at
	local check
	check = function(premature)

		if not premature then

			local res, err
			-- do the heartbeat
			if default_opts._sync_target_host ~= '' then
				res, err = util.heartbeat_http({
					sync_target_host = default_opts._sync_target_host,
					sync_target_port = default_opts._sync_target_port,
					biz_config       = _biz_config
				})
			else
				--_LOG_"_sync_target_host is blank, scheduling job fails"
				return
			end


			if res then
				if _biz_config["sys"]["biz"] == "skywalker" and res.domainbizmap then
				  local domainbizmap = res.domainbizmap
				  if _biz_config["sys"]["domainbizmap_version"] ~= domainbizmap["domainbizmap_version"] then
					_domainbizmap = util.table_copy(domainbizmap["data"])
					_biz_config["sys"]["domainbizmap_version"] = domainbizmap["domainbizmap_version"]
				  end
				end

                -- update the _ruleset_defs
                if res.data then
					_ruleset_defs_cow["_active"]  = false
					_ruleset_defs_cow["rulesets"] = util.table_copy(_ruleset_defs["rulesets"])
					-- do offset jump calculations for each app's rulesets
					-- this is also lazily handled in exec() for rulesets
					-- that dont appear here
					local data = res.data

					for app_name,_ in pairs(data) do
						if data[app_name] then
							local app_info = data[app_name]

							if not _biz_config[app_name] then
							  _biz_config[app_name] = {}
							end

							-- update bwl
							if 0 == ngx.worker.id() then
								if app_info["bl_version"]  then
									_biz_config[app_name]["bl_version"] = app_info["bl_version"]
									bwl.update_deser(app_info["black_list"])
								end

								if app_info["wl_version"]  then
									_biz_config[app_name]["wl_version"] = app_info["wl_version"]
									bwl.update_deser(app_info["white_list"])
								end
							end

							-- update qiyi_mode
							if app_info["qiyi_mode"] then
								_biz_config[app_name]["qiyi_mode"] = app_info["qiyi_mode"]
							end

							-- update mode and ct_header
							if app_info["ct_mode"] then
								_biz_config[app_name]["ct_mode"] = app_info["ct_mode"]
								if app_info["ct_header"] then
									_biz_config[app_name]["ct_header"] = app_info["ct_header"]
								end
							end

							-- update sample rate
							if app_info["sample_rate"] then
								_biz_config[app_name]["sample_rate"] = app_info["sample_rate"]
							end

							-- update client_ip_arg
							if app_info["client_ip_arg"] then
								_biz_config[app_name]["client_ip_arg"] = app_info["client_ip_arg"]
							end

							-- update ruleset
							if app_info["ruleset"] then
								_ruleset_cache[app_name] = app_info["ruleset"]

								-- clear this app's ruleset
								_ruleset_defs_cow["rulesets"][app_name] = {}

								-- keep each app's ruleset is calculated in order
								for _,type in ipairs(default_opts._active_rulesets) do

									if (app_info["ruleset"][type]) then
										local rs = util.table_copy(app_info["ruleset"][type])
										_calculate_offset(rs)
										_ruleset_defs_cow["rulesets"][app_name][type] = rs
									end

								end

								_biz_config[app_name]["version"] = app_info["version"]
							end
						end
					end

					-- copy on write
					_ruleset_defs_cow["_active"] = true
					_ruleset_defs["_active"]     = false
					_ruleset_defs["rulesets"]    = util.table_copy(_ruleset_defs_cow["rulesets"])
					_ruleset_defs["_active"]     = true
				end
			else
				logger.err_log("failed to heartbeat, err: " .. err)
			end

			local ok, err = new_timer(delay, check)
			if not ok then
				logger.err_log("failed to create timer, err: " .. err)
				return
			end
		end
	end

	local ok, err = new_timer(delay, check)
	if not ok then
		logger.err_log("failed to create timer, err: " .. err)
		return
	end
end

-- main entry point
function _M.exec(self)
	local biz_host = ngx.var.host
	if not _domainbizmap[biz_host] then
		return
	end

	-- get biz_name from nginx variable
	local biz_name  = _domainbizmap[biz_host]
	local biz_ct_mode  = "INACTIVE"
	local biz_qiyi_mode = "INACTIVE"
	local sample_rate = 100

	-- make sure initialization process have ran before exec
	if not self.init_flag then
		logger.err_log("Waf may not initialize.")
		return
	end

	if not biz_name then
		logger.err_log("biz_name is blank.")
		return
	end

	if not _biz_config[biz_name] then
		logger.err_log("no " .. biz_name .. " sync information.")
		return
    end

	local biz_ct_mode  = _biz_config[biz_name]["ct_mode"] or _INACTIVE
	local biz_qiyi_mode = _biz_config[biz_name]["qiyi_mode"] or _INACTIVE

	if biz_ct_mode == _INACTIVE and biz_qiyi_mode == _INACTIVE then
		return
	end

	local phase = ngx.get_phase()

	if not phase_t.is_valid_phase(phase) then
		logger.err_log("WAF should not be run in phase " .. phase)
		return
	end

	local start = util.get_micro_time()

	local ctx         = ngx.ctx.lua_resty_waf or tab_new(0, 30)
	local collections = ctx.collections or tab_new(0, 45)

	ctx.lrw_initted   = true
	ctx.start         = start
	ctx.col_lookup    = ctx.col_lookup or tab_new(0, 3)
	ctx.log_entries   = ctx.log_entries or {}
	ctx.log_entries_n = ctx.log_entries_n or 0
	ctx.storage       = ctx.storage or {}
	ctx.transform     = ctx.transform or {}
	ctx.transform_key = ctx.transform_key or {}
	ctx.t_header_set  = ctx.t_header_set or false
	ctx.phase         = phase
	ctx.match_n       = ctx.match_n or 0
	ctx.nameservers   = self._nameservers
	ctx.qiyi_mode     = biz_qiyi_mode
	ctx.ct_mode       = biz_ct_mode
	ctx.client_ip_arg = "default"
	ctx.sample_rate   = 100
	ctx.biz_name      = biz_name
	ctx.action        = "PASS"
	--默认请求不绕过长亭
	ctx.bypass_changting = false


	if _biz_config[biz_name]["sample_rate"] then
		ctx.sample_rate = _biz_config[biz_name]["sample_rate"]
	end

	if _biz_config[biz_name]["client_ip_arg"] then
		ctx.client_ip_arg = _biz_config[biz_name]["client_ip_arg"]
	end

	-- pre-initialize the TX collection
	ctx.storage["TX"]    = ctx.storage["TX"] or {}
	ctx.col_lookup["TX"] = "TX"

	-- see https://groups.google.com/forum/#!topic/openresty-en/LVR9CjRT5-Y
	if ctx.altered == true then
		--_LOG_"Transaction was already altered, not running!"
		return
	end

	-- populate the collections table
	if opts.collections then
		for k, v in pairs(opts.collections) do
			collections[k] = v
		end
	else
		collections_t.lookup[phase](self, collections, ctx)
	end

	-- don't run through the rulesets if we're going to be here again
	-- (e.g. multiple chunks are going through body_filter)
	if ctx.short_circuit then return end

	-- store the collections table in ctx, which will get saved to ngx.ctx
	ctx.collections = collections

	-- build rulesets
	if self.need_merge then
		_merge_rulesets(self)
	end

	-- set up tracking tables and flags if we're using redis for persistent storage
	--[[
	if (self._storage_backend == 'redis') then
		self._storage_redis_delkey_n = 0
		self._storage_redis_setkey_t = false
		self._storage_redis_delkey   = {}
		self._storage_redis_setkey   = {}
	end
	--]]

	--先执行自研引擎
	if biz_qiyi_mode ~= _INACTIVE then
		--_LOG_"Beginning run of phase " .. phase
		local _rulesets = util.choose_rulesets(_ruleset_defs, _ruleset_defs_cow)

		for _, ruleset in ipairs(self._active_rulesets) do
			repeat
				if not _rulesets["rulesets"][biz_name][ruleset] then
					break
				end

				--_LOG_"Beginning ruleset " .. ruleset

				local rs = _rulesets["rulesets"][biz_name][ruleset]

				local offset = 1
				local rule   = rs[phase][offset]

				while rule do
					local id = rule.id

					--_LOG_"Processing rule " .. id

					local returned_offset = _process_rule(self, rule, collections, ctx)
					if returned_offset then
						offset = offset + returned_offset
					else
						offset = nil
					end

					if not offset then break end

					rule = rs[phase][offset]
				end
			until true
		end
	end

	--后执行长亭引擎
	--若长亭模式为开启或观察，且不绕过长亭引擎时，则添加header，将请求转发到长亭引擎
	if biz_ct_mode ~= _INACTIVE and ctx.bypass_changting == false then
		--add X-APISIX-CT-WAF-Switch to turn on changting functionality
		ngx.req.set_header("X-APISIX-CT-WAF-Switch", "ENABLE_CT")
		--add X-APISIX-CT-WAF-Info to transmit encoded data for waf backend
		ngx.req.set_header("X-APISIX-CT-WAF-Info", _biz_config[biz_name]["ct_header"])
	end

	_finalize(self, ctx)
end

-- instantiate a new instance of the module
function _M.new(self)
	-- we need a separate copy of this table since we will
	-- potentially override values with set_option
	local t = util.table_copy(default_opts)

	t.transaction_id = random.random_bytes(10)

	-- handle conditions where init() wasnt called
	-- and the default rulesets weren't merged
	if (not t._active_rulesets) then
		t.need_merge = true
	end

	return setmetatable(t, mt)
end

-- configuraton wrapper for per-instance options
function _M.set_option(self, option, value, data)
	if (type(value) == "table") then
		for _, v in ipairs(value) do
			_M.set_option(self, option, v, data)
		end
	else
		if (options.lookup[option]) then
			options.lookup[option](self, value, data)
		else
			local _option = "_" .. option
			self[_option] = value
		end
	end
end

-- configuraton wrapper for default options
function _M.default_option(option, value, data)
	if (type(value) == "table") then
		for _, v in ipairs(value) do
			_M.default_option(option, v, data)
		end
	else
		if (options.lookup[option]) then
			options.lookup[option](default_opts, value, data)
		else
			local _option = "_" .. option
			default_opts[_option] = value
		end
	end
end

-- reset the given option to its static default
function _M.reset_option(self, option)
	local _option = "_" .. option
	self[_option] = opts.defaults[_option]
end

-- init_by_lua handler precomputations
function _M.init(business_names)
	_biz_config["sys"] = {}
	_biz_config["sys"]["waf"] = _M.version
	logger.notice_log("qiyi-waf: initializing ... , version: " .. _M.version)

	if jit then
		_biz_config["sys"]["lua"] = jit.version
	else
		_biz_config["sys"]["lua"] = _VERSION
	end

	if business_names and business_names ~= "" and business_names ~= "{{business_name}}" then
		if business_names == "all" then
			_biz_config["sys"]["biz"] = "all"
		elseif business_names == "skywalker" then
			_biz_config["sys"]["biz"] = "skywalker"
		else
			_biz_config["sys"]["biz"] = "specific"
			-- business names are seprated with ","
			string.gsub(business_names, "([^,]+)", function(value)
				_biz_config[value] = {}
			end)
		end
	else
		logger.err_log("Business name is invalid.")
		return
	end

    logger.notice_log("qiyi-waf: sync log here!")
    logger.notice_log(default_opts._sync_target_host)
    logger.notice_log(default_opts._sync_target_port)
	-- rquest for the latest rulesets
	local resp, err
	if default_opts._sync_target_host ~= '' then
		resp, err = util.sync_with_wafmng({
			sync_target_host = default_opts._sync_target_host,
			sync_target_port = default_opts._sync_target_port,
			biz_config       = _biz_config
		})
	else
    return
  end

	if resp and resp.code == "W0000" then
		if resp["global"] then

			-- init the opts' value
			for global_key,value in pairs(resp["global"]) do
				-- contains event log target host and port
				--          err log target host and port
				--          dc, sync_delay ...
				default_opts[global_key] = value
			end
		end

		if resp["data"] then
			-- do an initial rule merge based on default_option calls
			-- this prevents have to merge every request in scopes
			-- which do not further alter elected rulesets
			_merge_rulesets(default_opts)

			_ruleset_defs["rulesets"] = {}
			-- do offset jump calculations for each app's rulesets
			-- this is also lazily handled in exec() for rulesets
			-- that dont appear here
			local data = resp["data"]
			for biz_name,_ in pairs(data) do
				for biz_key,value in pairs(data[biz_name]) do
					if biz_key ~= "ruleset" then
						if biz_key == "bl_version" then
							_biz_config[biz_name][biz_key] = data[biz_name][biz_key]
							bwl.update_deser(data[biz_name]["black_list"])
						elseif biz_key == "wl_version" then
							_biz_config[biz_name][biz_key] = data[biz_name][biz_key]
							bwl.update_deser(data[biz_name]["white_list"])
						elseif biz_key ~= "black_list" and biz_key ~= "white_list" then
							if not _biz_config[biz_name] then
								_biz_config[biz_name] = {}
							end
							_biz_config[biz_name][biz_key] = data[biz_name][biz_key]
						end
					else
						-- initialize the ruleset of the business
						_ruleset_cache[biz_name] = data[biz_name]["ruleset"]
						_ruleset_defs["rulesets"][biz_name] = {}

						if data[biz_name]["ruleset"] then
							-- keep the each business's rulesets is calculated in order
							for _,type in ipairs(default_opts._active_rulesets) do
								if (data[biz_name]["ruleset"][type]) then
									local rs = util.table_copy(data[biz_name]["ruleset"][type])
									_calculate_offset(rs)
									_ruleset_defs["rulesets"][biz_name][type] = rs
								end
							end
						end
					end
				end
			end
			_ruleset_defs["_active"] = true
    end

    if resp['domainbizmap'] then
        _biz_config["sys"]["domainbizmap_version"] = resp['domainbizmap']["domainbizmap_version"]
        _domainbizmap = resp['domainbizmap']['data']
    end
	else
		logger.err_log("initialization from server failure")
		return
	end

	-- clear this flag if we handled additional rulesets
	-- so its not passed to new objects
	default_opts.need_merge = false
	-- set init_flag to true
	default_opts.init_flag = true
end

function _M.access_by_lua(self)

	local biz_host = ngx.var.host
	if not _domainbizmap[biz_host] then
		return
	end

	local ctx = ngx.ctx.lua_resty_waf or {}

	-- record the elapsed time of processing a request in waf
	--local w_finish = util.get_micro_time()

	--if ctx.start and w_finish >= ctx.start then
	--	ctx.w_process_time = w_finish - ctx.start
	--end
	if ngx.var.t1k_blocked == "403" and ctx.ct_mode == "ACTIVE" then
		ctx.action = "CT_DENY"
		ngx.exit(ngx.HTTP_FORBIDDEN)
	end
	if ngx.var.t1k_blocked == "403" or ctx.action ~= "PASS" then
		return
	end

    if ctx.biz_name == '~sec_test' then
	    --黑名单功能
        local rule = [[ {"id": "BW1", "name": "黑名单IP-封禁", "dry_run": false, "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}], "action": "forbid"} ]]
	    --local rule = [[ {"id": "BW2", "name": "黑名单UA-验证页", "dry_run": false, "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "HEADER", "value": "User-Agent"}], "action": "verify"} ]]
        local jdata = cjson.decode(rule)
        local action = util.check_bwlist(rule, ctx)
        local alerts = {rule_id = jdata.id, name = jdata.name, action = jdata.action, rule_type = "黑白名单检查"}
        if action == 'DENY' or action == 'VERIFY' then
		    ctx.log_entries_n = ctx.log_entries_n + 1
		    ctx.log_entries[ctx.log_entries_n] = alerts
	    end
	    if action == 'DENY' and not jdata.dry_run then
		    ctx.action = "BW_DENY"
		    ngx.exit(ngx.HTTP_FORBIDDEN)
        elseif action == 'DENY' and jdata.dry_run then
		    ctx.action = "BW_ALERT"
        elseif action == 'VERIFY' and not jdata.dry_run then
		    ctx.action = "BW_VERIFY"
            actions.disruptive_lookup[action](self, ctx, ctx.action)
        elseif action == 'VERIFY' and jdata.dry_run then
            ctx.action = "BW_ALERT"
        end
    end

    if ctx.biz_name == '~sec_test' then
        --限频功能
        local rule = [[ {"id": "1", "name": "满足条件-限流", "dry_run": false, "is_match_method": true, "match_method": {"limit": 10, "scope": "URL", "period": 60, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http(s)", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "Limit Rate", "limit_rate_limit": 5, "limit_rate_period": 60}, "expire_period": 600} ]]
        --local rule = [[ {"id": "2", "name": "满足条件-封禁", "dry_run": false, "is_match_method": true, "match_method": {"limit": 10, "scope": "URL", "period": 60, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "forbid"}, "expire_period": 600} ]]
        --local rule = [[ {"id": "3", "name": "满足条件-验证页", "dry_run": false, "is_match_method": true, "match_method": {"limit": 10, "scope": "URL", "period": 60, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "verify"}, "expire_period": 600} ]]
        --local rule = [[ {"id": "4", "name": "黑名单-验证页", "dry_run": false, "is_match_method": false, "match_method": {"limit": null, "scope": "URL Prefix", "period": null, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "verify"}, "expire_period": 600} ]]
        --local rule = [[ {"id": "5", "name": "黑名单-封禁", "dry_run": false, "is_match_method": false, "match_method": {"limit": null, "scope": "URL Prefix", "period": null, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "forbid"}, "expire_period": 600} ]]
        --local rule = [[ {"id": "6", "name": "黑名单-限流", "dry_run": false, "is_match_method": false, "match_method": {"limit": null, "scope": "URL Prefix", "period": null, "policy": "sec-test.waf.qiyi.domain/redistest", "scheme": "http", "target_type": [{"key": "IP", "value": "REMOTE_ADDR"}, {"key": "GET", "value": "id"}]}, "action": {"action": "Limit Rate", "limit_rate_limit": 10, "limit_rate_period": 60}, "expire_period": 600} ]]
        local jdata = cjson.decode(rule)
        local match_url = jdata.match_method.scheme .. '://' .. jdata.match_method.policy
        local current_url

        if ngx.var.server_port == "80" or ngx.var.server_port == "443" then
            if jdata.match_method.scheme == 'http(s)' then
                current_url = 'http(s)://' .. ngx.req.get_headers().host .. ngx.var.uri
            else
                current_url = ngx.var.scheme .. '://' .. ngx.req.get_headers().host .. ngx.var.uri
            end
        else
            if jdata.match_method.scheme == 'http(s)' then
                current_url = 'http(s)://' .. ngx.req.get_headers().host .. ':' .. ngx.var.server_port .. ngx.var.uri
            else
                current_url = ngx.var.scheme .. '://' .. ngx.req.get_headers().host .. ':' .. ngx.var.server_port .. ngx.var.uri
            end
        end
        if (jdata.match_method.scope == "URL" and match_url == current_url) or (jdata.match_method.scope == "URL Prefix" and current_url:sub(1, #match_url) == match_url) then
            local action = util.access_limit_rate(rule, ctx)
            local alerts = {rule_id = jdata.id, name = jdata.name, action = jdata.action.action, rule_type = "访问频率控制"}
            if action == 'DENY' or action == 'VERIFY' then
                ctx.log_entries_n = ctx.log_entries_n + 1
                ctx.log_entries[ctx.log_entries_n] = alerts
            end
            if action == 'DENY' and not jdata.dry_run then
                ctx.action = "RATE_DENY"
                ngx.exit(ngx.HTTP_FORBIDDEN)
            elseif action == 'DENY' and jdata.dry_run then
                ctx.action = "RATE_ALERT"
            elseif action == 'VERIFY' and not jdata.dry_run then
                ctx.action = "RATE_VERIFY"
                actions.disruptive_lookup[action](self, ctx, ctx.action)
            elseif action == 'VERIFY' and jdata.dry_run then
                ctx.action = "RATE_ALERT"
            end
        end
    end
end

function _M.header_filter(self)
	local ctx = ngx.ctx.lua_resty_waf or {}
	if ngx.var.tx_blocked == "403" and ctx.ct_mode == "ACTIVE" then
		ctx.action = "CT_DENY"
		ngx.status = 403
		for k, v in pairs(ngx.resp.get_headers()) do
			if k ~= 'date' and k ~= 'server' and k ~= 'content-type' and k ~= 'connection' and k ~= 'content-length' then
				ngx.header[k] = nil
			end
		end
	end
	if ctx.action == "Q_DENY" or ctx.action == 'CT_DENY' or ctx.action == 'RATE_DENY' or ctx.action == 'BW_DENY' then
		ngx.header.content_length = nil
	end
end


function _M.body_filter(self)
	local ctx = ngx.ctx.lua_resty_waf or {}
	-- modify response body by replacing nginx to Qiyi-WAF
	if ctx.action == "Q_DENY" or ctx.action == "CT_DENY" or ctx.action == 'RATE_DENY' or ctx.action == 'BW_DENY' then
		if ngx.var.tx_blocked == "403" then
			ngx.arg[1] = "<html>\n" ..
					"<head><title>403 Forbidden</title></head>\n" ..
					"<body bgcolor=\"white\">\n" ..
					"<center><h1>403 Forbidden</h1></center>\n" ..
					"<hr><center>" .. ctx.action .. ': ' .. self._forbidden_res_info .. "</center>\n" ..
					"</body>\n" ..
					"</html>\n"
			ngx.arg[2] = true
		else
			ngx.arg[1] = string.gsub(ngx.arg[1], "openresty", ctx.action .. ': ' .. self._forbidden_res_info)
		end
	end

	if ctx.lrw_initted then
		local t_finish = util.get_micro_time()

		if t_finish > ctx.start then
			ctx.t_process_time = t_finish - ctx.start
		end
	end

	-- record response body size
	if ctx.collections then
		if not ctx.collections["RESPONSE_BODY_SIZE"] then
			ctx.collections["RESPONSE_BODY_SIZE"] = #ngx.arg[1]
		else
			ctx.collections["RESPONSE_BODY_SIZE"] = ctx.collections["RESPONSE_BODY_SIZE"] + #ngx.arg[1]
		end
	end
	return
end

-- push log data regarding matching rule(s) to the configured target
-- in the case of socket or file logging, this data will be buffered
function _M.write_log_events(self)
	-- there is a small bit of code duplication here to get our context
	-- because this lives outside exec()
	local ctx = ngx.ctx.lua_resty_waf or {}
	if ctx.opts then
		self = ctx.opts
	end

	--If not initialed, return without printing log.
	if (not ctx.lrw_initted) then
		return
	end

	--[[
	if ctx.altered ~= true and self._event_log_altered_only then
		-- logger.err_log("not logging a request that wasn't altered")
		return
	end
	--]]

	local entry = {
		id             = self.transaction_id,
		dc             = self._dc,
		business_name  = ctx.biz_name,
		server_addr    = ctx.collections["SERVER_ADDRESS"],
		client_ip      = ctx.collections["CLIENT_IP"],
		remote_addr    = ctx.collections["REMOTE_ADDR"],
		protocal       = ctx.collections["PROTOCOL"],
		req_uri        = ctx.collections["REQUEST_URI"],
		uri            = ctx.collections["URI"],
		req_args       = ctx.collections["REQUEST_ARGS"],
		method         = ctx.collections["METHOD"],
		headers        = ctx.collections["REQUEST_HEADERS"],
		resp_status    = ngx.var.status,
		timestamp      = ngx.time(),
		alerts         = ctx.log_entries,
		action         = ctx.action,
		port           = ngx.var.server_port,
		reqLen         = ctx.collections["ARGS_COMBINED_SIZE"],
		respLen        = ctx.collections["RESPONSE_BODY_SIZE"],
	}

	if ctx.attack_type and ctx.attack_level then
		entry.attack_type  = ctx.attack_type
		entry.attack_level = ctx.attack_level
	end

	entry.r_process_time = ctx.r_process_time or 0
	--entry.w_process_time = ctx.w_process_time or 0
	entry.t_process_time = ctx.t_process_time or 0

	--For no threat requests, sample log
	if ctx.action ~= "Q_DENY" and ctx.action ~= "CT_DENY" and ctx.action ~= "REDIRECT_VERIFY" and ctx.action ~= "ALERT" and ctx.action ~= "RATE_DENY" and ctx.action ~= "RATE_VERIFY" and ctx.action ~= "RATE_ALERT" and ctx.action ~= 'BW_DENY' and ctx.action ~= 'BW_VERIFY' and ctx.action ~= 'BW_ALERT' then
		local sample_rate = ctx.sample_rate
		math.randomseed(util.get_micro_time())
		local random = math.random(1,100)
		if random > sample_rate then
			return
		end
	end

	if ctx.action == "ALERT" then
		entry.action = "ALERT"
	end
	-- in order to record process time
	--benchmark.record(ngx.var.BUSINESS_NAME, entry.r_process_time, entry.w_process_time, entry.t_process_time)
	logger.write_log_events[self._event_log_target](self, entry)
end

return _M
