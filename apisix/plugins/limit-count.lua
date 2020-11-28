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
local limit_local_new = require("resty.limit.count").new
local core = require("apisix.core")
local plugin_name = "limit-count"
local ipairs      = ipairs
local limit_redis_cluster_new
local limit_redis_new
do
    local redis_src = "apisix.plugins.limit-count.limit-count-redis"
    limit_redis_new = require(redis_src).new

    local cluster_src = "apisix.plugins.limit-count.limit-count-redis-cluster"
    limit_redis_cluster_new = require(cluster_src).new
end


local schema = {
    type = "object",
    properties = {
        second = {type = "integer", minimum = 1},
        minute = {type = "integer",  minimum = 1},
        hour = {type = "integer",  minimum = 1},
        key = {
            type = "string",
            enum = {"qiyi_client_ip", "server_addr", "http_x_real_ip", "total",
                    "http_x_forwarded_for", "consumer_name", "credential"},
            default = "total",
        },
        rejected_code = {
            type = "integer", minimum = 200, maximum = 600,
            default = 429,
        },
        policy = {
            type = "string",
            enum = {"local", "redis", "redis-cluster"},
            default = "local",
        },
        fault_tolerant = {
            type = "boolean",
            default = true,
        }
    },
    required = {"key"},
    dependencies = {
        policy = {
            oneOf = {
                {
                    properties = {
                        policy = {
                            enum = {"local"},
                        },
                    },
                },
                {
                    properties = {
                        policy = {
                            enum = {"redis"},
                        },
                        redis_host = {
                            type = "string", minLength = 2
                        },
                        redis_port = {
                            type = "integer", minimum = 1, default = 6379,
                        },
                        redis_password = {
                            type = "string", minLength = 0,
                        },
                        redis_timeout = {
                            type = "integer", minimum = 1, default = 1000,
                        },
                    },
                    required = {"redis_host"},
                },
                {
                    properties = {
                        policy = {
                            enum = {"redis-cluster"},
                        },
                        redis_cluster_nodes = {
                            type = "array",
                            minItems = 2,
                            items = {
                                type = "string", minLength = 2, maxLength = 100
                            },
                        },
                        redis_password = {
                            type = "string", minLength = 0,
                        },
                        redis_timeout = {
                            type = "integer", minimum = 1, default = 1000,
                        },
                    },
                    required = {"redis_cluster_nodes"},
                }
            }
        }
    }
}


local _M = {
    version = 0.4,
    priority = 1002,
    name = plugin_name,
    schema = schema,
}

local function self_check(conf)
    local ordered_periods = {"second", "minute", "hour"}
    local has_value
    local invalid_order

    for i, v in ipairs(ordered_periods) do
        if conf[v] then
            has_value = true
            for t = i, #ordered_periods do
                if conf[ordered_periods[t]] and conf[ordered_periods[t]] < conf[v] then
                    invalid_order = "The limit for " .. ordered_periods[t].. " cannot be lower than the limit for " .. v
                end
            end
        end
    end

    if not has_value then
      return false, "You need to set at least one limit: second, minute, hour"
    elseif invalid_order then
      return false, invalid_order
    end

    return true, nil
end

function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    if conf.policy == "redis" then
        if not conf.redis_host then
            return false, "missing valid redis option host"
        end
    end

    ok, err = self_check(conf)
    if not ok then
        return false, err
    end

    return true
end

local EXPIRATIONS = {
  second = 1,
  minute = 60,
  hour = 3600,
}

local WINDOW = {
  [1] = "second",
  [60] = "minute",
  [3600] = "hour",
}

local function create_limit_objs(conf)
    core.log.info("create new limit-count plugin instances table")

    local objtab = core.table.new(#EXPIRATIONS, 0)
    local ordered_periods = {"second", "minute", "hour"}
    local temp_obj, err
    if not conf.policy or conf.policy == "local" then
        for i, v in ipairs(ordered_periods) do
            if conf[v] then
                temp_obj, err = limit_local_new("plugin-" .. plugin_name .. "-" .. v, conf[v],
                                            EXPIRATIONS[v])
                if not temp_obj then
                    return nil, err
                end
                core.table.insert(objtab, temp_obj)
            end
        end
    end

    if conf.policy == "redis" then
        for _, v in ipairs(ordered_periods) do
            if conf[v] then
                temp_obj, err = limit_redis_new("plugin-" .. plugin_name .. "-" .. v,
                                           conf[v], EXPIRATIONS[v], conf)
                if not temp_obj then
                    return nil, err
                end
                core.table.insert(objtab, temp_obj)
            end
        end
    end

    if conf.policy == "redis-cluster" then
        for _, v in ipairs(ordered_periods) do
            if conf[v] then
                temp_obj, err = limit_redis_cluster_new("plugin-" .. plugin_name .. "-" .. v,
                                           conf[v], EXPIRATIONS[v], conf)
                if not temp_obj then
                    return nil, err
                end
                core.table.insert(objtab, temp_obj)
            end
        end
    end

    return objtab, nil
end


local function get_identifier(conf, ctx)
    local identifier
    if conf.key == "consumer_name" then
        identifier = ctx.consumer and ctx.consumer_id
        -- fallback to credential: passport set ngx.var.uid = credential
        if not identifier and ngx.var.uid then
            identifier = ngx.var.uid
        end
    elseif conf.key == "total" then
        identifier = "total"
    elseif conf.key == "credential" then
        identifier = ctx.consumer.auth_conf.password or ctx.consumer.auth_conf.key
    end

    if not identifier then identifier = ngx.var.qiyi_client_ip end

    return identifier
end

function _M.access(conf, ctx)
    core.log.info("ver: ", ctx.conf_version)
    local fault_tolerant = conf.fault_tolerant
    local lims, err = core.lrucache.plugin_ctx(plugin_name, ctx,
                                              create_limit_objs, conf)
    if not lims then
        core.log.error("failed to fetch limit.count object table: ", err)
        if not fault_tolerant then
            return 500, "failed to fetch limit.count object table"
        end
    end

    local key
    if conf.key == "credential" then
        key = (ctx.consumer.auth_conf.password or ctx.consumer.auth_conf.key or "") .. ctx.conf_type .. ctx.conf_version
    elseif conf.key == "total" then
        key = "" .. ctx.conf_type .. ctx.conf_version
    else
        key = (ctx.var[conf.key] or "") .. ctx.conf_type .. ctx.conf_version
    end
    core.log.info("limit key: ", key)

    local delay, remaining
    local lim_key = {}
    for i, lim in ipairs(lims) do
        delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                ngx.var.identifier = get_identifier(conf, ctx)
                return conf.rejected_code, "API rate limit exceeded!!"
            end

            core.log.error("failed to limit req: ", err)
            if not fault_tolerant then
                return 500, {error_msg = "failed to limit count: " .. err}
            end
        end

        lim_key[WINDOW[lim.window]] = remaining
    end

    for k, v in pairs(lim_key) do
        core.response.set_header("X-RateLimit-Limit" .. "-" .. k, conf[k],
                                 "X-RateLimit-Remaining" .. "-" .. k, v)
    end

end


return _M
