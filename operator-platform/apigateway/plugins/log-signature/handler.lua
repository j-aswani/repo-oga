-- Copyright (C) Kong Inc.
require "kong.tools.utils" -- ffi.cdefs
local kong_meta = require "kong.meta"

local ffi = require "ffi"
local cjson = require "cjson"
local system_constants = require "lua_system_constants"

local kong = kong

local O_CREAT = system_constants.O_CREAT()
local O_WRONLY = system_constants.O_WRONLY()
local O_APPEND = system_constants.O_APPEND()
local S_IRUSR = system_constants.S_IRUSR()
local S_IWUSR = system_constants.S_IWUSR()
local S_IRGRP = system_constants.S_IRGRP()
local S_IROTH = system_constants.S_IROTH()

local oflags = bit.bor(O_WRONLY, O_CREAT, O_APPEND)
local mode = ffi.new("int", bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH))

local C = ffi.C

-- fd tracking utility functions
local file_descriptors = {}

local function log(conf, message)
  local msg = cjson.encode(message) .. "\n"
  kong.log.notice("Handled request, exporting signature to file...", msg)
  
  local fd = file_descriptors[conf.path]
  if not fd then
    fd = C.open(conf.path, oflags, mode)
    if fd < 0 then
      local errno = ffi.errno()
      kong.log.err("failed to open the file: ", ffi.string(C.strerror(errno)))
    else
      file_descriptors[conf.path] = fd
    end
  end

  C.write(fd, msg, #msg)
end

local ExmapleHandler = {
  PRIORITY = 9,
  VERSION = kong_meta.version,
}

function ExmapleHandler:log(conf)
  --  https://docs.konghq.com/gateway/latest/plugin-development/pdk/kong.log/#konglogserialize
  local data = kong.log.serialize()
  local message = {
    url = data.request.url,
    signature = data.request.headers[conf.signature_header_name]
  }
  log(conf, message)
end


return ExmapleHandler