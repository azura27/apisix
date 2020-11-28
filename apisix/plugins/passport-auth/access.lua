local cjson            = require "cjson.safe"
local ck               = require "resty.cookie"
local pl_string        = require "pl.stringx"
local http             = require "resty.http"
local core             = require("apisix.core")
local req_set_uri_args = ngx.req.set_uri_args
local req_get_uri_args = ngx.req.get_uri_args
local ngx              = ngx
local request          = ngx.req
local tostring         = tostring

local COOKIE = "cookie"
local COOKIE_FIELD = "authcookie"

local _M = {}

-- get cookie from P000001
local function retrieve_credentials(conf, cookie_header_value)
    local authcookie
    if cookie_header_value then
        local cookie, err = ck:new()
        if not cookie then
            core.log.error(err)
            return core.response.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, err)
        end
        -- get P000001 cookie
        authcookie, err = cookie:get(conf.cookie_name)
        if not authcookie then
            core.log.error("[passport-auth] failed to get value with key " .. conf.cookie_name .. " in cookie ", err)
            return nil
        end
    end
    return authcookie
end

local function passport_authenticate(given_authcookie, conf)
    local is_authenticated
    local err, suppressed_err, ok
    local res, body, data

    local http_client = http.new()
    http_client:set_timeout(conf.timeout)
    ok, err = http_client:connect(conf.passport_host, conf.passport_port)
    if not ok then
        core.log.error("[passport-auth] failed to connect to " .. conf.passport_host .. ":" .. tostring(conf.passport_port) .. ": ", err)
        return core.response.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, err)
    end

    res, err = http_client:request({
      path = conf.passport_path,
      method = "GET",
      query = {
        authcookie = given_authcookie,
        fields = conf.request_field
      },
      headers = {
        ["Content-Type"] = "text/plain",
      },
    })
    if not res then
        return core.response.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, err)
    end

    if res.status ~= ngx.HTTP_OK then
        return nil, "[passport-auth] response with status " .. res.status
    end

    body = res:read_body()

    if not body then
        return nil, "[passport-auth] no content from passport"
    end

    local data = cjson.decode(body)

    if not data then
        return nil, "[passport-auth] failed to decode response to json"
    end

    local keys = pl_string.split(conf.resolve_key, ".")
    for _, v in ipairs(keys) do
        if data and data[v] then
            data = data[v]
        else
            return nil, "[passport-auth] there is no content for key " .. conf.resolve_key
        end
    end

    if type(data) ~= "string" then
        return nil, "[passport-auth] only support return value in type of string"
    end

    ok, suppressed_err = http_client:set_keepalive(conf.keepalive)
    if not ok then
        core.log.error("[passport-auth] failed to keepalive to " .. conf.passport_host .. ":" .. tostring(conf.passport_port))
        return core.response.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, suppressed_err)
    end

    return data, err
end

-- get uid via authcookie
local function load_credential(given_authcookie, conf)
    core.log.debug("[passport-auth] authenticating user against Passport server: " .. conf.passport_host .. ":" .. conf.passport_port)
    local credential = {}
    local upstream_querystring_value, err = passport_authenticate(given_authcookie, conf)
    if err ~= nil then core.log.error(err) end
    if not upstream_querystring_value then
        return nil
    end
    credential[conf.upstream_querystring_name] = upstream_querystring_value
    return credential
end

-- authenticate with passport and get uid
local function authenticate(conf, given_cookie)
    core.log.debug("[passport-auth] the authcookie is  " .. given_cookie)
    -- get uid in cache
    local credential = load_credential(given_cookie, conf)

    return credential and credential[conf.upstream_querystring_name], credential
end

local function set_consumer(conf, credential)
    local querystring = req_get_uri_args()
    if conf.hide_credentials then
        request.clear_header(COOKIE)
        querystring[COOKIE_FIELD] = nil
    end
    -- keep consistent with apisix's other auth plugins
    ngx.ctx.consumer = {}
    ngx.ctx.consumer_id = credential
    querystring[conf.upstream_querystring_name] = credential

    ngx.var.uid = credential
    -- as req_get_uri_args will decode the query string and we need to encode it before setting
    req_set_uri_args(ngx.encode_args(querystring))
end

local function do_authentication(conf)
    local headers = request.get_headers()
    local cookie_value = headers[COOKIE]
    local authcookie
    local uid_credential

    -- first try to get cookie from header if not then try to get it from query string
    if cookie_value then
        authcookie = retrieve_credentials(conf, cookie_value)   -- search
    else
        local querystring = req_get_uri_args()
        authcookie = querystring[COOKIE_FIELD]
    end

    -- If cookie is missing, uid is empty string
    if not authcookie then
        core.log.warn("[passport-auth] Cookie is missing in headrer or quering string")
        if not conf.forward_to_backend then
            return false, {status = conf.custom_code or 401, message = "Invalid credentials" }
        end
    else
        -- authenticate with passport and get uid in credential
        local is_authorized, credential = authenticate(conf, authcookie)

        if not is_authorized then
            core.log.warn("[passport-auth] Failed to get uid from passport with give cookie ", authcookie)
            if not conf.forward_to_backend then
                return false, {status = conf.custom_code or 401, message = "Invalid authentication credentials" }
            end
        else
            uid_credential = credential[conf.upstream_querystring_name]
        end
    end

    -- add uid to querystring
    set_consumer(conf, uid_credential)

    return true
end

function _M.execute(conf)
    -- authentication cookie and set uid
    local ok, err = do_authentication(conf)
    if not ok then
        return core.response.exit(err.status, err.message)
    end
end

return _M
