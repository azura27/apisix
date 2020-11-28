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
local core = require("apisix.core")
local pairs       = pairs
local type        = type
local ngx         = ngx


local schema = {
    type = "object",
    properties = {
        body = {
            description = "body to response",
            type = "string",
            default = "mock API OK",
        },
        headers = {
            description = "new headers for repsonse",
            type = "object",
            default = {},
        },
        defaultcode = {
            description = "default status code for each request Methods",
            type = "integer",
            default = 200,
        },
        code = {
            description = "status code for spec request Method",
            type = "object",
            default = {},
        },
    },
    additionalProperties = false,
}

local plugin_name = "api-mock"

local _M = {
    version = 0.1,
    priority = 4000,
    name = plugin_name,
    schema = schema,
}


function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        core.log.error("schema check error:", err)
        return false, err
    end

    if conf.headers then
        for field, value in pairs(conf.headers) do
            if not ( type(field) == 'string'
                    and (type(value) == 'string' or type(value) == 'number') )
               or #field == 0 then
                return false, 'invalid field or value in header'
            end
        end
    end

    return true
end

function _M.access(conf, ctx)
    local body = ""
    body = body .. conf.body

    local headers = {}
    if conf.headers then
        for field, value in pairs(conf.headers) do
            core.table.insert(headers, field)
            core.table.insert(headers, value)
        end
    end

    local code = conf.defaultcode

    if conf.code then
        for field, value in pairs(conf.code) do
            if ngx.req.get_method() == field then
                    code = tonumber(value)
                    core.log.info("code define:", field, "   ", code)
                    break
            end
        end
    end

    local field_cnt = #headers
    for i = 1, field_cnt, 2 do
        ngx.header[headers[i]] = headers[i+1]
    end

    --return code, body
    core.response.exit(code, body)
end

return _M
