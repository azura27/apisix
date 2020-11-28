--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local core          = require("apisix.core")
local lua_resty_waf = require "apisix.plugins.qiyi-waf.waf"
local debug         = debug
local xpcall        = xpcall

local plugin_name = "qiyi-waf"


local schema = {
    type = "object",
    properties = {
    },
}


local _M = {
    version = 0.1,
    priority = 11100,
    name = plugin_name,
    schema = schema,
}


function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.init_worker()
    local waf = lua_resty_waf:new()
    lua_resty_waf.scheduling_heartbeat()
end


function _M.rewrite_by_lua()
    local waf = lua_resty_waf:new()
    xpcall(function() waf:exec() end, function() ngx.log(ngx.ERR, debug.traceback()) end)
end


function _M.access()
    local waf = lua_resty_waf:new()
    xpcall(function() waf:access_by_lua() end, function() ngx.log(ngx.ERR, debug.traceback()) end)
end


function _M.header_filter()
    local waf = lua_resty_waf:new()
    xpcall(function() waf:header_filter() end, function() ngx.log(ngx.ERR, debug.traceback()) end)
end


function _M.body_filter()
    local waf = lua_resty_waf:new()
    xpcall(function() waf:body_filter() end, function() ngx.log(ngx.ERR, debug.traceback()) end)
end


function _M.log()
    local waf = lua_resty_waf:new()
    xpcall(function() waf:write_log_events() end, function() ngx.log(ngx.ERR, debug.traceback()) end)
end

return _M
