-- Copyright (C) Yichun Zhang (agentzh)


require "apisix.plugins.qiyi-waf.wlib.resty.core.uri"
require "apisix.plugins.qiyi-waf.wlib.resty.core.hash"
require "apisix.plugins.qiyi-waf.wlib.resty.core.base64"
require "apisix.plugins.qiyi-waf.wlib.resty.core.regex"
require "apisix.plugins.qiyi-waf.wlib.resty.core.exit"
require "apisix.plugins.qiyi-waf.wlib.resty.core.shdict"
require "apisix.plugins.qiyi-waf.wlib.resty.core.var"
require "apisix.plugins.qiyi-waf.wlib.resty.core.ctx"
require "apisix.plugins.qiyi-waf.wlib.resty.core.misc"
require "apisix.plugins.qiyi-waf.wlib.resty.core.request"
require "apisix.plugins.qiyi-waf.wlib.resty.core.response"
require "apisix.plugins.qiyi-waf.wlib.resty.core.time"
require "apisix.plugins.qiyi-waf.wlib.resty.core.worker"


local base = require "apisix.plugins.qiyi-waf.wlib.resty.core.base"


return {
    version = base.version
}
