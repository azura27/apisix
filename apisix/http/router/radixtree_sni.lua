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
local get_request      = require("resty.core.base").get_request
local radixtree_new    = require("resty.radixtree").new
local core             = require("apisix.core")
local ngx_ssl          = require("ngx.ssl")
local config_util      = require("apisix.core.config_util")
local ipairs	       = ipairs
local type             = type
local error            = error
local str_find         = string.find
local aes              = require "resty.aes"
local assert           = assert
local str_gsub         = string.gsub
local ngx_decode_base64 = ngx.decode_base64
local ssl_certificates
local radixtree_router
local radixtree_router_ver
local prefix = ngx.config.prefix()


local _M = {
    version = 0.1,
    server_name = ngx_ssl.server_name,
}


local function create_router(ssl_items)
    local ssl_items = ssl_items or {}

    local route_items = core.table.new(#ssl_items, 0)
    local idx = 0

    local local_conf = core.config.local_conf()
    local iv
    if local_conf and local_conf.apisix
       and local_conf.apisix.ssl
       and local_conf.apisix.ssl.key_encrypt_salt then
        iv = local_conf.apisix.ssl.key_encrypt_salt
    end
    local aes_128_cbc_with_iv = (type(iv)=="string" and #iv == 16) and
            assert(aes:new(iv, nil, aes.cipher(128, "cbc"), {iv=iv})) or nil

    for _, ssl in config_util.iterate_values(ssl_items) do
        if ssl.value ~= nil and
            (ssl.value.status == nil or ssl.value.status == 1) then  -- compatible with old version

            local j = 0
            local sni
            if type(ssl.value.snis) == "table" and #ssl.value.snis > 0 then
                sni = core.table.new(0, #ssl.value.snis)
                for _, s in ipairs(ssl.value.snis) do
                    j = j + 1
                    sni[j] = s:reverse()
                end
            else
                sni = ssl.value.sni:reverse()
            end

            -- decrypt private key
            if aes_128_cbc_with_iv ~= nil and
                not str_find(ssl.value.key, "---") then
                local decrypted = aes_128_cbc_with_iv:decrypt(ngx_decode_base64(ssl.value.key))
                if decrypted == nil then
                    core.log.error("decrypt ssl key failed. key[", ssl.value.key, "] ")
                else
                    ssl.value.key = decrypted
                end
            end

            idx = idx + 1
            route_items[idx] = {
                paths = sni,
                handler = function (api_ctx)
                    if not api_ctx then
                        return
                    end
                    api_ctx.matched_ssl = ssl
                    api_ctx.matched_sni = sni
                end
            }
        end
    end

    core.log.info("route items: ", core.json.delay_encode(route_items, true))
    -- for testing
    if #route_items > 1 then
        core.log.info("we have more than 1 ssl certs now")
    end
    local router, err = radixtree_new(route_items)
    if not router then
        return nil, err
    end

    return router
end

local function read_file(path)
    local file, err = io.open(path, "rb") -- r read mode and b binary mode
    if not file then
        return nil, err
    end

    local content = file:read("*a")  -- *a or *all reads the whole file
    file:close()
    return content, nil
end

local function cert_value_parse(cert)
    local file_path, str_cert
    local err = nil
    -- if cert is read from file,file_path must length lt 128
    if #cert < 128 then
        local tmp = str_find(cert, "/")
        if tmp == nil then
            file_path = prefix .. "conf/" .. cert
            str_cert, err = read_file(file_path)
            if str_cert then
                return str_cert, nil   
            end
        else 
            str_cert, err = read_file(cert)
            if str_cert then
                return str_cert, nil   
            end
        end
        return cert, "read failed:" .. err
    end
    return cert, err
end

local function set_pem_ssl_key(cert, pkey)
    local r = get_request()
    if r == nil then
        return false, "no request found"
    end

    local cert_value, err = cert_value_parse(cert)
    if err then
        return false, "failed to get cert value: " .. err
    end

    local parse_cert, err = ngx_ssl.parse_pem_cert(cert_value)
    if parse_cert then
        local ok, err = ngx_ssl.set_cert(parse_cert)
        if not ok then
            return false, "failed to set PEM cert: " .. err
        end
    else
        return false, "failed to parse PEM cert: " .. err
    end

    local parse_pkey, err = ngx_ssl.parse_pem_priv_key(pkey)
    if parse_pkey then
        local ok, err = ngx_ssl.set_priv_key(parse_pkey)
        if not ok then
            return false, "failed to set PEM priv key: " .. err
        end
    else
        return false, "failed to parse PEM priv key: " .. err
    end

    return true
end


function _M.match_and_set(api_ctx)
    local err
    if not radixtree_router or
       radixtree_router_ver ~= ssl_certificates.conf_version then
        radixtree_router, err = create_router(ssl_certificates.values)
        if not radixtree_router then
            return false, "failed to create radixtree router: " .. err
        end
        radixtree_router_ver = ssl_certificates.conf_version
    end

    local sni
    sni, err = ngx_ssl.server_name()
    if type(sni) ~= "string" then
        return false, "failed to fetch SSL certificate: " .. (err or "not found")
    end

    core.log.debug("sni: ", sni)

    local sni_rev = sni:reverse()
    local ok = radixtree_router:dispatch(sni_rev, nil, api_ctx)
    if not ok then
        core.log.error("failed to find any SSL certificate by SNI: ", sni)
        return false
    end


    if type(api_ctx.matched_sni) == "table" then
        local matched = false
        for _, msni in ipairs(api_ctx.matched_sni) do
            if sni_rev == msni or not str_find(sni_rev, ".", #msni, true) then
                matched = true
            end
        end
        if not matched then
            local log_snis = core.json.encode(api_ctx.matched_sni, true)
            if log_snis ~= nil then
                log_snis = str_gsub(log_snis:reverse(), "%[", "%]")
                log_snis = str_gsub(log_snis, "%]", "%[", 1)
            end
            core.log.warn("failed to find any SSL certificate by SNI: ",
                          sni, " matched SNIs: ", log_snis)
            return false
        end
    else
        if str_find(sni_rev, ".", #api_ctx.matched_sni, true) then
            core.log.warn("failed to find any SSL certificate by SNI: ",
                          sni, " matched SNI: ", api_ctx.matched_sni:reverse())
            return false
        end
    end

    local matched_ssl = api_ctx.matched_ssl
    core.log.info("debug - matched: ", core.json.delay_encode(matched_ssl, true))

    ngx_ssl.clear_certs()

    ok, err = set_pem_ssl_key(matched_ssl.value.cert, matched_ssl.value.key)
    if not ok then
        return false, err
    end

    -- multiple certificates support.
    if matched_ssl.value.certs then
        for i = 1, #matched_ssl.value.certs do
            local cert = matched_ssl.value.certs[i]
            local key = matched_ssl.value.keys[i]

            ok, err = set_pem_ssl_key(cert, key)
            if not ok then
                return false, err
            end
        end
    end

    return true
end


function _M.ssls()
    if not ssl_certificates then
        return nil, nil
    end

    return ssl_certificates.values, ssl_certificates.conf_version
end


function _M.init_worker()
    local err
    ssl_certificates, err = core.config.new("/ssl", {
                        automatic = true,
                        item_schema = core.schema.ssl,
                    })
    if not ssl_certificates then
        error("failed to create etcd instance for fetching ssl certificates: "
              .. err)
    end
end


return _M
