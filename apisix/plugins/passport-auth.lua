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
local access = require("apisix.plugins.passport-auth.access")

local request_field_values = {
    "userinfo",
    "qiyi_vip",
    "vip_info",
    "tv_vip_info",
    "qiyi_tennis_vip",
    "tv_tennis_vip",
    "tv_children_vip",
    "fun_vip",
    "sport_vip"
}

local schema = {
    type = "object",
    properties = {
        passport_host = {
            description = "user passport get api's host",
            type = "string",
            default = "passport.qiyi.domain",
        },
        passport_port = {
            description = "user passport api's host port",
            type = "integer",
            default = "80",
        },
        passport_path = {
            description = "user passport api's request uri",
            type = "string",
            default = "/apis/user/info.action",
        },
        cookie_name = {
            description = "authcookie for user passport api",
            type = "string",
            default = "P00001",
        },
        request_field = {
            type = "string",
            enum = request_field_values,
            default = "userinfo"
        },
        resolve_key = {
            type = "string",
            default = "data.userinfo.uid"
        },
        upstream_querystring_name = {
            type = "string",
            default = "uid"
        },
        hide_credentials = {
            description = "hide_credentials on/off",
            type = "boolean",
            default = true,
        },
        forward_to_backend = {
            description = "after api called failed, whether to forward to upstream",
            type = "boolean",
            default = false,
        },
        custom_code = {
            description = "status code after api called failed && not forward_to_backend",
            type = "integer",
            default = 401,
        },
        timeout = {
            description = "timeout for requesting user passport api(ms)",
            type = "integer",
            default = 10000,
        },
        keepalive = {
            description = "time to stay keepalive(ms)",
            type = "integer",
            default = 60000,
        }
    },
    additionalProperties = false,
}

local plugin_name = "passport-auth"

local _M = {
    version = 0.1,
    priority = 2540,
    type = 'auth',
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)

    if not ok then
        return false, err
    end

    return true
end

function _M.access(conf, ctx)
    access.execute(conf)
end

return _M
