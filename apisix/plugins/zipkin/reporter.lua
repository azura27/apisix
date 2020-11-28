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
local ngx_socket_udp = ngx.socket.udp
local to_hex = require "resty.string".to_hex
local cjson = require "cjson".new()
local local_conf = require("apisix.core.config_local").local_conf()
local core = require("apisix.core")
cjson.encode_number_precision(16)
local assert = assert
local type = type
local setmetatable = setmetatable
local math = math
local tostring = tostring


local _M = {}
local mt = { __index = _M }


local span_kind_map = {
    client = "CLIENT",
    server = "SERVER",
    producer = "PRODUCER",
    consumer = "CONSUMER",
}

local SERVICE_NAME = local_conf.apisix.zipkin
             and local_conf.apisix.zipkin.rover_service_name


function _M.new(conf)
    local host = conf.host
    local port = conf.port
    local service_name = conf.service_name
    local server_port = conf.server_port
    local server_addr = conf.server_addr
    return setmetatable({
        host = host,
        port = port,
        service_name = service_name,
        server_addr = server_addr,
        server_port = server_port,
        pending_spans = {},
        pending_spans_n = 0,
    }, mt)
end


function _M.report(self, span)
    local span_context = span:context()
    local zipkin_tags = {}
    for k, v in span:each_tag() do
        -- Zipkin tag values should be strings
        zipkin_tags[k] = tostring(v)
    end

    local span_kind = zipkin_tags["span.kind"]
    zipkin_tags["span.kind"] = nil

    local localEndpoint = {
        serviceName = SERVICE_NAME,
        ipv4 = self.server_addr,
        port = self.server_port,
        -- TODO: ip/port from ngx.var.server_name/ngx.var.server_port?
    }

    local remoteEndpoint do
        local peer_port = span:get_tag "peer.port" -- get as number
        if peer_port then
            zipkin_tags["peer.port"] = nil
            remoteEndpoint = {
                ipv4 = zipkin_tags["peer.ipv4"],
                port = peer_port, -- port is *not* optional
            }
            zipkin_tags["peer.ipv4"] = nil
            zipkin_tags["peer.ipv6"] = nil
        else
            remoteEndpoint = cjson.null
        end
    end

    local zipkin_span = {
        traceId = to_hex(span_context.trace_id),
        name = span.name,
        parentId = span_context.parent_id and
                    to_hex(span_context.parent_id) or nil,
        id = to_hex(span_context.span_id),
        kind = span_kind_map[span_kind],
        timestamp = span.timestamp * 1000000,
        duration = math.floor(span.duration * 1000000), -- zipkin wants integer
        -- TODO: debug?
        localEndpoint = localEndpoint,
        remoteEndpoint = remoteEndpoint,
        tags = zipkin_tags,
        annotations = span.logs
    }

    local i = self.pending_spans_n + 1
    self.pending_spans[i] = zipkin_span
    self.pending_spans_n = i
    ngx.var.is_traced = true
    ngx.var.traceId = to_hex(span_context.trace_id)
end

function _M.flush(self, conf)
    if self.pending_spans_n == 0 then
        return true
    end

    local udp_message = {}
    -- venus udp format
    udp_message["udp_topic"] = conf.topic
    udp_message["message"] = self.pending_spans

    local pending_spans = cjson.encode(udp_message)
    core.log.info("udp_message send to venus:", pending_spans)
    self.pending_spans = {}
    self.pending_spans_n = 0

    local sock = ngx_socket_udp()
    sock:settimeout(conf.timeout)

    local ok, err = sock:setpeername(conf.host, conf.port)
    if not ok then
        return nil, "[zipkin-reporter] could not connect to ", conf.host, ":", conf.port, ": ", err
    end

    local ok, err
    ok, err = sock:send(pending_spans)

    if not ok then
        return nil, "failed to send: " .. err
    end

    ok, err = sock:close()

    if not ok then
        return nil, "failed to close connection from " .. self.host .. ":" .. tostring(self.port) .. ": " .. err
    end
    return true
end


return _M
