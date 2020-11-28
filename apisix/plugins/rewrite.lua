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
local core        = require("apisix.core")
local access      = require("apisix.plugins.rewrite.access")
local plugin_name = "rewrite"
local type        = type

local schema = {
    type = "object",
    properties = {
        regex = {
            description = "new uri that substitute from client uri " ..
                          "for upstream",
            type        = "string",
        },
        replacement = {
            description = "new URL for upstream",
            type        = "string",
        },
        flag = {
            description = "action for upstream",
            type    = "string",
            enum    = {"last" , "break", "redirect", "permanent"},
            default = "break",
        },
    },
    required = {"regex", "replacement"},
    additionalProperties = false,
}


local _M = {
    version  = 0.1,
    priority = 1008,
    name     = plugin_name,
    schema   = schema,
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
