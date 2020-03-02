local balancer_resty = require("balancer.resty")
local ck = require("resty.cookie")
local resty_chash = require("resty.chash")
local ngx_balancer = require("ngx.balancer")
local split = require("util.split")
local util = require("util")

local _M = balancer_resty:new()
local DEFAULT_COOKIE_NAME = "route"

function _M.cookie_name(self)
  return self.cookie_session_affinity.name or DEFAULT_COOKIE_NAME
end

function _M.new(self)
  local o = {
    chash = nil,
    alternative_backends = nil,
    cookie_session_affinity = nil,
    traffic_shaping_policy = nil
  }

  setmetatable(o, self)
  self.__index = self

  return o
end

function _M.get_cookie(self)
  local cookie, err = ck:new()
  if not cookie then
    ngx.log(ngx.ERR, err)
  end

  return cookie:get(self:cookie_name())
end

function _M.set_cookie(self, value)
  local cookie, err = ck:new()
  if not cookie then
    ngx.log(ngx.ERR, err)
  end

  local cookie_path = self.cookie_session_affinity.path
  if not cookie_path then
    cookie_path = ngx.var.location_path
  end

  local cookie_data = {
    key = self:cookie_name(),
    value = value,
    path = cookie_path,
    httponly = true,
    secure = ngx.var.https == "on",
  }

  if self.cookie_session_affinity.expires and self.cookie_session_affinity.expires ~= "" then
      cookie_data.expires = ngx.cookie_time(ngx.time() + tonumber(self.cookie_session_affinity.expires))
  end

  if self.cookie_session_affinity.maxage and self.cookie_session_affinity.maxage ~= "" then
    cookie_data.max_age = tonumber(self.cookie_session_affinity.maxage)
  end

  local ok
  ok, err = cookie:set(cookie_data)
  if not ok then
    ngx.log(ngx.ERR, err)
  end
end

function _M.get_last_failure()
  return ngx_balancer.get_last_failure()
end

local function get_failed_upstreams()
  local indexed_upstream_addrs = {}
  local upstream_addrs = split.split_upstream_var(ngx.var.upstream_addr) or {}

  for _, addr in ipairs(upstream_addrs) do
    indexed_upstream_addrs[addr] = true
  end

  return indexed_upstream_addrs
end

local function should_set_cookie(self)
  local host = ngx.var.host
  if ngx.var.server_name == '_' then
    host = ngx.var.server_name
  end

  if self.cookie_session_affinity.locations then
    local locs = self.cookie_session_affinity.locations[host]
    if locs == nil then
      -- Based off of wildcard hostname in ../certificate.lua
      local wildcard_host, _, err = ngx.re.sub(host, "^[^\\.]+\\.", "*.", "jo")
      if err then
        ngx.log(ngx.ERR, "error: ", err);
      elseif wildcard_host then
        locs = self.cookie_session_affinity.locations[wildcard_host]
      end
    end

    if locs ~= nil then
      for _, path in pairs(locs) do
        if ngx.var.location_path == path then
          return true
        end
      end
    end
  end

  return false
end

local function should_change_upstream(self)
  return self.cookie_session_affinity.change_on_failure and self.get_last_failure() ~= nil
end

local function can_use_upstream(self, upstream, failed_upstreams)
  return upstream and not should_change_upstream(self) and not failed_upstreams[upstream]
end

local function get_param(name)
  local cookie_name = name
  local query_param_name = name
  local header_name = 'x-' .. name
  local value = ''

  local cookie = ck:new()
  if cookie then
    value = cookie:get(cookie_name)
    if value then
      return value
    end
  end

  local query_params = ngx.req.get_uri_args()
  if query_params then
    value = query_params[query_param_name]
    if value then
      return value
    end
  end

  local headers = ngx.req.get_headers()
  if headers then
    value = headers[header_name]
    if value then
      return value
    end
  end

  return ''
end

function _M.balance(self)
  local failed_upstreams = get_failed_upstreams()

  local cookie_val = self:get_cookie()
  if cookie_val then
    local upstream = self:use_upstream_by_hash(cookie_val, failed_upstreams)
    if upstream then
      return upstream
    end
  end

  -- balancing by client IP is working only in 'persistent' mode currently
  if self.instance.map then -- is 'persistent' mode?
    local route_param = get_param('lumetric-route')
    if route_param then
      local upstream = self:use_upstream_by_hash(route_param, failed_upstreams)
      if upstream then
        return upstream
      end
    end

    local sticky_param = get_param('lumetric-sticky')
    if sticky_param == 'off' or sticky_param == 'false' then
      return self:use_new_upstream(failed_upstreams)
    end

    local headers = ngx.req.get_headers()
    local real_ip = ngx.var.remote_addr
    for _, name in ipairs({ 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip' }) do
      if headers[name] then
        real_ip = headers[name]
        break
      end
    end

    local req_key = (real_ip or '') .. "\t" .. (headers["user-agent"] or '')
    local upstream = self:use_upstream_by_key(req_key, failed_upstreams)
    if upstream then
      return upstream
    end
  end

  return self:use_new_upstream(failed_upstreams)
end

function _M.use_new_upstream(self, failed_upstreams)
  local new_upstream, hash = self:pick_new_upstream(failed_upstreams)
  if not new_upstream then
    ngx.log(ngx.WARN, string.format("failed to get new upstream; using upstream %s", new_upstream))
  elseif should_set_cookie(self) then
    self:set_cookie(hash)
  end
  return new_upstream
end


function _M.use_upstream_by_key(self, key, failed_upstreams)
  local upstream = self.chash:find(key)
  if can_use_upstream(self, upstream, failed_upstreams) then
    for hash, endpoint in pairs(self.instance.map) do
      if endpoint == upstream then
        if should_set_cookie(self) then
          self:set_cookie(hash)
        end
        return upstream
      end
    end
  end
  return nil
end

function _M.use_upstream_by_hash(self, hash, failed_upstreams)
  local upstream = self.instance:find(hash)
  if can_use_upstream(self, upstream, failed_upstreams) then
    if should_set_cookie(self) then
      self:set_cookie(hash)
    end
    return upstream
  end
  return nil
end

function _M.sync(self, backend)
  -- reload balancer nodes
  balancer_resty.sync(self, backend)

  self.traffic_shaping_policy = backend.trafficShapingPolicy
  self.alternative_backends = backend.alternativeBackends
  self.cookie_session_affinity = backend.sessionAffinityConfig.cookieSessionAffinity
  self.chash = resty_chash:new(util.get_nodes(backend.endpoints))
end

return _M
