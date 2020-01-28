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
  return upstream ~= nil and not should_change_upstream(self) and not failed_upstreams[upstream]
end

function _M.balance(self)
  local failed_upstreams = get_failed_upstreams()

  local cookie_val = self:get_cookie()
  if cookie_val then
    local upstream_from_cookie = self.instance:find(cookie_val)
    if can_use_upstream(self, upstream_from_cookie, failed_upstreams) then
      return upstream_from_cookie
    end
  end

  -- balancing by client IP is working only in 'persistent' mode currently
  if self.instance.map then -- is 'persistent' mode?
    local headers = ngx.req.get_headers()
    local real_ip = ngx.var.remote_addr
    for _, name in ipairs({ 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip' }) do
      if headers[name] then
        real_ip = headers[name]
        break
      end
    end

    local req_key = (real_ip or '') .. "\t" .. (headers["user-agent"] or '')
    local upstream_from_request = self.chash:find(req_key)
    if can_use_upstream(self, upstream_from_request, failed_upstreams) then
      local hash
      for key, endpoint in pairs(self.instance.map) do
        if endpoint == upstream_from_request then
          hash = key
          break
        end
      end
      if hash and should_set_cookie(self) then
        self:set_cookie(hash)
      end
      return upstream_from_request
    end
  end

  local new_upstream, hash = self:pick_new_upstream(failed_upstreams)
  if not new_upstream then
    ngx.log(ngx.WARN, string.format("failed to get new upstream; using upstream %s", new_upstream))
  elseif should_set_cookie(self) then
    self:set_cookie(hash)
  end

  return new_upstream
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
