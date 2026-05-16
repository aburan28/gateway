-- Security sandbox for Lua execution in Envoy Gateway
-- Blocks dangerous functions and validates paths to prevent access to sensitive system resources

-- ============================================================================
-- CRITICAL PATHS
-- ============================================================================

local critical_paths = {
    "/etc",
    "/proc",
    "/sys",
    "/certs",
    "/var/run/secrets",
}

-- ============================================================================
-- CRITICAL ENVIRONMENT VARIABLES
-- ============================================================================

local critical_env_vars = {
    ["PWD"] = true,
}

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

local function to_absolute_normalized_path(path)
    if not path or type(path) ~= "string" then
        return path
    end
    
    local normalized_separators = path:gsub("\\", "/")
    
    local absolute_path
    if normalized_separators:match("^/") then
        absolute_path = normalized_separators
    else
        absolute_path = "/" .. normalized_separators
    end
    
    return absolute_path:match("^(.-)/*$")
end

local function contains_traversal(path)
    if not path or type(path) ~= "string" then
        return false
    end
    
    if path:match("/%.%./") or path:match("^%.%./") or path:match("/%.%.$") or path:match("^%.%.$") or
       path:match("\\%.%.\\") or path:match("^%.%.\\") or path:match("\\%.%.$") or path:match("^%.%.$") then
        return true
    end
    
    return false
end

local function is_critical_path(path)
    if not path or type(path) ~= "string" then
        return false
    end
    
    local normalized = to_absolute_normalized_path(path)
    
    for _, critical_path in ipairs(critical_paths) do
        local normalized_critical = to_absolute_normalized_path(critical_path)
        local escaped_critical = normalized_critical:gsub("%-", "%%-")
        
        if normalized == normalized_critical or normalized:match("^" .. escaped_critical .. "/") then
            return true
        end
    end
    
    return false
end

local function validate_path(path)
    if not path or type(path) ~= "string" then
        return
    end
    
    if contains_traversal(path) then
        error("path traversals are restricted for security")
    end
    
    if is_critical_path(path) then
        error("access to critical path " .. path .. " is restricted for security")
    end
end

local function is_critical_env_var(env_var)
    if not env_var or type(env_var) ~= "string" then
        return false
    end
    return critical_env_vars[env_var:upper()] == true
end

-- ============================================================================
-- COMPLETELY BLOCKED FUNCTIONS
-- ============================================================================

io.popen = nil
os.execute = nil
os.exit = nil
require = nil
loadfile = nil
dofile = nil
package = nil
debug = nil
load = nil
loadstring = nil
rawget = nil
rawset = nil
getmetatable = nil
setmetatable = nil
-- gopher-lua emulates Lua 5.1, which exposes getfenv/setfenv. Without nulling
-- them, user code can recover the globals table after _G = nil via
-- `getfenv(0)` and call back into io.*, os.*, etc.
getfenv = nil
setfenv = nil
-- coroutine.* lets user code yield/resume across the executor, escaping the
-- single-shot deadline used by the validator. It is not needed for any
-- documented envoy_on_request/envoy_on_response surface.
coroutine = nil
-- Block access to global table to prevent _G["_unsafe_*"] bypasses
_G = nil

-- ============================================================================
-- BOUNDED STRING OPERATIONS
-- ============================================================================
-- `string.rep(s, n)` and `string.format("%<n>s", x)` allocate proportional to
-- a user-controlled count; the gopher-lua RegistryMaxSize bounds the Lua
-- registry, not Go-heap allocations. Cap to a few MB so the validator can't
-- be turned into an OOM amplifier for the controller pod.

local _max_string_size = 1024 * 1024  -- 1 MiB

do
    local _unsafe_string_rep = string.rep
    string.rep = function(s, n, sep)
        if type(s) ~= "string" or type(n) ~= "number" then
            return _unsafe_string_rep(s, n, sep)
        end
        local sep_len = (type(sep) == "string") and #sep or 0
        if n < 0 or #s * n + sep_len * math.max(n - 1, 0) > _max_string_size then
            error("string.rep result exceeds size limit (" .. _max_string_size .. " bytes)")
        end
        return _unsafe_string_rep(s, n, sep)
    end
end

-- ============================================================================
-- SANITIZED IO FUNCTIONS (path validation)
-- ============================================================================

do
    local _unsafe_io_open = io.open
    local _unsafe_io_input = io.input
    local _unsafe_io_output = io.output
    local _unsafe_io_lines = io.lines

    io.open = function(filename, mode)
        validate_path(filename)
        return _unsafe_io_open(filename, mode)
    end

    io.input = function(file)
        if file == nil then
            return _unsafe_io_input()
        end
        if type(file) == "string" then
            validate_path(file)
        end
        return _unsafe_io_input(file)
    end

    io.output = function(file)
        if file == nil then
            return _unsafe_io_output()
        end
        if type(file) == "string" then
            validate_path(file)
        end
        return _unsafe_io_output(file)
    end

    io.lines = function(filename)
        if filename then
            validate_path(filename)
        end
        return _unsafe_io_lines(filename)
    end
end

-- ============================================================================
-- SANITIZED OS FUNCTIONS (path/env var validation)
-- ============================================================================

do
    local _unsafe_os_remove = os.remove
    local _unsafe_os_rename = os.rename
    local _unsafe_os_getenv = os.getenv
    local _unsafe_os_setenv = os.setenv

    os.remove = function(pathname)
        validate_path(pathname)
        return _unsafe_os_remove(pathname)
    end

    os.rename = function(oldname, newname)
        validate_path(oldname)
        validate_path(newname)
        return _unsafe_os_rename(oldname, newname)
    end

    os.getenv = function(varname)
        if is_critical_env_var(varname) then
            error("access to critical environment variable " .. varname .. " is restricted for security")
        end
        return _unsafe_os_getenv(varname)
    end

    os.setenv = function(varname, value)
        if is_critical_env_var(varname) then
            error("setting critical environment variable " .. varname .. " is restricted for security")
        end
        return _unsafe_os_setenv(varname, value)
    end
end
