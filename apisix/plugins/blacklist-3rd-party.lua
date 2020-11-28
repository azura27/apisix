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
local core      = require("apisix.core")
local http      = require "resty.http"
local cjson     = require "cjson.safe"


local schema = {
    type = "object",
    properties = {
        blacklist_host = {
            description = "blacklist-3rd-party api's host setting",
            type = "string",
            default = "mp-api.qiyi.domain",
        },
        blacklist_port = {
            description = "blacklist-3rd-party api's host port setting",
            type = "integer",
            default = "80",
        },
        blacklist_path = {
            description = "blacklist-3rd-party request uri",
            type = "string",
            default = "/uv/api/2.0/forbiddance/checkByUid",
        },
        test_mode = {
            description = "blacklist-3rd-party test mode state on/off",
            type = "boolean",
            default = false,
        },
        test_uid = {
            description = "uid defined when blacklist-3rd-party test mode on",
            type = "string",
        },
        forward_to_backend = {
            description = "after api called failed, whether to forward to upstream",
            type = "boolean",
            default = false,
        },
        custom_code = {
            description = "status code after api called failed && not forward_to_backend",
            type = "integer",
            default = 403,
        },
        timeout = {
            description = "timeout for requesting blacklist-3rd-party(ms)",
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


local plugin_name = "blacklist-3rd-party"


local _M = {
    version = 0.1,
    priority = 2499,        -- TODO: add a type field, may be a good idea
    name = plugin_name,
    schema = schema,
}

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        core.log.error("schema check error:", err)
        return false, err
    end

    return true
end

local function blacklist_query(conf, uid)
    local is_black = false
    local err, suppressed_err, ok
    local res, body, data

    local http_client = http.new()
    http_client:set_timeout(conf.timeout)
    ok, err = http_client:connect(conf.blacklist_host, conf.blacklist_port)
    if not ok then
        return nil, "[blacklist-3rd-party] failed to connect to " .. conf.blacklist_host .. ":" .. tostring(conf.blacklist_port) .. ": ", err
    end

    res, err = http_client:request({
        path = conf.blacklist_path,
        method = "GET",
        query = {
            uid = uid,
        },
        headers = {
            ["Content-Type"] = "text/plain",
        },
    })
    if not res then
        return nil, "[blacklist-3rd-party] failed to get response from" .. conf.blacklist_host .. ":" .. tostring(conf.blacklist_port) .. ": ", err
    end

    if res.status ~= ngx.HTTP_OK then
        return nil, "[blacklist-3rd-party] response with status " .. res.status
    end

    body = res:read_body()

    if not body then
        return nil, "[blacklist-3rd-party] no content from body"
    end

    local data = cjson.decode(body)
    core.log.info("response code from blacklist  ", tostring(data.code))

    if not data then
        return nil, "[blacklist-3rd-party] failed to decode response to json"
    end

    -- Response format
    --[[
      {
        code: 0,
        msg: "success",
        data: "true"
      }
      "code is 0" means that application ends successfully, if not, then an error occurs;
      "data is true" means that uid is in then blacklist, and false means that not in the list
    --]]

    if data and data["code"] and data["data"] then
        if data["code"] ~= 0 then
            return nil, "[blacklist-3rd-party] code field is not 0"
        else
            if data["data"] == 'true' then is_black = true end
        end
    else
        return nil, "[blacklist-3rd-party] no code or data field in response"
    end

    ok, suppressed_err = http_client:set_keepalive(conf.keepalive)
    if not ok then
        core.log.error("[blacklist-3rd-party] failed to keepalive to ", conf.blacklist_host,  ":", tostring(conf.blacklist_port))
    end

    return is_black, nil
end

function _M.access(conf, ctx)
    local uid = ngx.var.uid

    if conf.test_mode then
        uid = conf.test_uid
    end

    if not uid or uid == '' then
        return
    end

    ngx.var.blacklist_3rd_party = "black-false"

    local is_blacked, err = blacklist_query(conf, uid)
    if err then
        ngx.var.blacklist_3rd_party = "black-failed"
        core.log.error("[blacklist_3rd_party] calling err:", err)
        if not conf.forward_to_backend then
            return conf.custom_code or 403, "Not allowed to visit"
        end
    end

    if is_blacked then
        ngx.var.blacklist_3rd_party = "black-true"
        return conf.custom_code or 403, "Not allowed to visit the content"
    end

end


return _M
