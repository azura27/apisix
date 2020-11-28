local core   = require("apisix.core")
local re_sub = ngx.re.sub
local str_sub = string.sub
local _M = {}


local function startswith(haystack, needle)
    return str_sub(haystack, 1, #needle) == needle
end

local actions = {
    ["break"] = function(uri) ngx.req.set_uri(uri, false) end,
    ["last"] = function(uri) ngx.exec(uri) end,
    ["redirect"] = function(uri) ngx.redirect(uri) end,
    ["permanent"] = function(uri) ngx.redirect(uri, 301) end
}

local function rewrite(conf)
    local regex = conf.regex
    local replacement = conf.replacement
    local flag = conf.flag

    if startswith(replacement, "http://") or startswith(replacement, "https://") or startswith(replacement, "$scheme") then
        return ngx.redirect(replacement)
    end

    local origin_uri = ngx.var.uri
    local uri, _, err = re_sub(origin_uri, regex, replacement, "o")
    if err then
        return core.response.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, err)
    end
    actions[flag](uri)
end

function _M.execute(conf)
    rewrite(conf)
end

return _M
