local io = require("io")
local cjson = require("cjson")

local _M = {}

local CACHE_VERSION = 1
local MAX_DIMENSION_KEYS = 50000
local TOP_N = 10
local memory_cache = {}
local IS_WINDOWS = (package and package.config and package.config:sub(1, 1) == "\\")
    or (jit and jit.os == "Windows")

local function empty_summary(date, source_exists, source_size)
    return {
        cache_version = CACHE_VERSION,
        date = date,
        source_exists = source_exists == true,
        source_size = source_size or 0,
        source_offset = 0,
        attacks = 0,
        whitelist_hits = 0,
        by_method = {},
        ip_counts = {},
        url_counts = {},
        top_ips = {},
        top_urls = {},
        dimension_overflow = false,
    }
end

local function file_size(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local size = f:seek("end") or 0
    f:close()
    return size
end

local function shell_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function windows_quote(value)
    return '"' .. tostring(value):gsub('"', '""') .. '"'
end

local function ensure_dir(path)
    local probe = io.open(path .. "/.probe", "a")
    if probe then
        probe:close()
        os.remove(path .. "/.probe")
        return true
    end
    if IS_WINDOWS then
        os.execute("if not exist " .. windows_quote(path) .. " mkdir " .. windows_quote(path))
    else
        os.execute("mkdir -p -- " .. shell_quote(path))
    end
    local check = io.open(path .. "/.probe", "a")
    if not check then return false end
    check:close()
    os.remove(path .. "/.probe")
    return true
end

local function read_cache(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local raw = f:read("*a")
    f:close()
    if not raw or raw == "" then return nil end
    local ok, obj = pcall(cjson.decode, raw)
    if not ok or type(obj) ~= "table" then return nil end
    if obj.cache_version ~= CACHE_VERSION or type(obj.date) ~= "string" then return nil end
    if type(obj.by_method) ~= "table" or type(obj.ip_counts) ~= "table" or type(obj.url_counts) ~= "table" then
        return nil
    end
    return obj
end

local function read_range_cache(path, days, today, today_source_size, day_cache_sizes)
    local f = io.open(path, "r")
    if not f then return nil end
    local raw = f:read("*a")
    f:close()
    if not raw or raw == "" then return nil end
    local ok, obj = pcall(cjson.decode, raw)
    if not ok or type(obj) ~= "table" then return nil end
    if obj.cache_version ~= CACHE_VERSION or tonumber(obj.range_days) ~= days
        or obj.today ~= today or tonumber(obj.today_source_size) ~= today_source_size then
        return nil
    end
    if type(obj.days) ~= "table" or type(obj.totals) ~= "table" or type(obj.day_cache_sizes) ~= "table" then return nil end
    for date, size in pairs(day_cache_sizes or {}) do
        if tonumber(obj.day_cache_sizes[date]) ~= tonumber(size) then return nil end
    end
    return obj
end

local function write_cache(path, summary)
    local dir = path:match("^(.*)[/\\][^/\\]+$")
    if not dir or not ensure_dir(dir) then return false end
    local suffix = tostring(os.time())
    if ngx and ngx.worker and ngx.worker.id then
        suffix = suffix .. "." .. tostring(ngx.worker.id())
    end
    local tmp_path = path .. ".tmp." .. suffix
    local f = io.open(tmp_path, "w")
    if not f then return false end
    local ok, encoded = pcall(cjson.encode, summary)
    if not ok or not encoded then
        f:close()
        os.remove(tmp_path)
        return false
    end
    f:write(encoded)
    f:close()
    local renamed = os.rename(tmp_path, path)
    if not renamed and IS_WINDOWS then
        -- Windows CRT rename cannot replace an existing file.
        os.remove(path)
        renamed = os.rename(tmp_path, path)
    end
    if not renamed then
        os.remove(tmp_path)
        return false
    end
    return true
end

local function inc_bounded(map, key, summary)
    if not key or key == "" then return end
    if map[key] ~= nil then
        map[key] = map[key] + 1
        return
    end
    local count = 0
    for _ in pairs(map) do count = count + 1 end
    if count >= MAX_DIMENSION_KEYS then
        summary.dimension_overflow = true
        return
    end
    map[key] = 1
end

local function sorted_top(map)
    local values = {}
    for key, count in pairs(map or {}) do
        values[#values + 1] = {key, count}
    end
    table.sort(values, function(a, b)
        if a[2] == b[2] then return tostring(a[1]) < tostring(b[1]) end
        return a[2] > b[2]
    end)
    local result = {}
    for i = 1, math.min(TOP_N, #values) do result[i] = values[i] end
    return result
end

local function aggregate_line(summary, line)
    if not line or line == "" then return end
    local ok, obj = pcall(cjson.decode, line)
    if not ok or type(obj) ~= "table" then return end
    local method = obj.attack_method or "Unknown"
    if method == "White_IP" then
        summary.whitelist_hits = summary.whitelist_hits + 1
        return
    end
    summary.attacks = summary.attacks + 1
    summary.by_method[method] = (summary.by_method[method] or 0) + 1
    inc_bounded(summary.ip_counts, obj.client_ip, summary)
    inc_bounded(summary.url_counts, obj.req_url, summary)
end

local function scan_file(path, summary, offset)
    local f = io.open(path, "r")
    if not f then return nil end
    if offset and offset > 0 then
        f:seek("set", offset)
        -- The previous scan stores an offset immediately after a full line.
        -- Skip no content when positioned at a line boundary; if a caller
        -- supplied an interior offset, discard only the partial line.
    end
    for line in f:lines() do aggregate_line(summary, line) end
    local end_offset = f:seek("end") or 0
    f:close()
    summary.source_offset = end_offset
    summary.source_size = end_offset
    summary.source_exists = true
    summary.top_ips = sorted_top(summary.ip_counts)
    summary.top_urls = sorted_top(summary.url_counts)
    return end_offset
end

function _M.load_day(date, log_path, cache_dir, immutable)
    local cache_path = cache_dir .. "/waf_" .. date .. ".json"
    local cached = memory_cache[cache_path]

    -- 已归档日期只信任统计文件；历史日志不会再被打开或 stat。
    if immutable then
        if not cached then cached = read_cache(cache_path) end
        if cached then
            memory_cache[cache_path] = cached
            return cached
        end
    end

    local source_size = file_size(log_path)

    if cached and source_size == cached.source_size and cached.source_offset == source_size then
        return cached
    end

    if not cached then cached = read_cache(cache_path) end

    if source_size == nil then
        if cached and cached.source_size == 0 then
            cached.source_exists = false
            memory_cache[cache_path] = cached
            return cached
        end
        local empty = empty_summary(date, false, 0)
        empty.source_offset = 0
        write_cache(cache_path, empty)
        memory_cache[cache_path] = empty
        return empty
    end

    if cached and cached.source_size == source_size and cached.source_offset == source_size then
        cached.source_exists = true
        memory_cache[cache_path] = cached
        return cached
    end

    local summary
    local start_offset = 0
    if cached and cached.source_size >= 0 and cached.source_offset == cached.source_size
        and cached.source_size < source_size then
        summary = cached
        start_offset = cached.source_offset
    else
        summary = empty_summary(date, true, source_size)
    end

    local scanned = scan_file(log_path, summary, start_offset)
    if not scanned then
        summary = cached or empty_summary(date, false, 0)
        memory_cache[cache_path] = summary
        return summary
    end
    write_cache(cache_path, summary)
    memory_cache[cache_path] = summary
    return summary
end

function _M.load_range(days, log_dir, now)
    days = math.min(math.max(tonumber(days) or 7, 1), 31)
    now = now or os.time()
    local cache_dir = _M.cache_dir(log_dir)
    local today = os.date("%Y-%m-%d", now)
    local today_path = log_dir .. "/waf_" .. today .. ".log"
    local today_source_size = file_size(today_path) or 0
    local day_cache_sizes = {}
    for i = days - 1, 0, -1 do
        local t = now - i * 86400
        local date = os.date("%Y-%m-%d", t)
        day_cache_sizes[date] = file_size(cache_dir .. "/waf_" .. date .. ".json") or -1
    end
    local range_path = cache_dir .. "/range_" .. tostring(days) .. ".json"
    local cached_range = read_range_cache(range_path, days, today, today_source_size, day_cache_sizes)
    if cached_range then return cached_range end

    local day_results = {}
    local totals_attacks = 0
    local totals_by_method = {}
    local totals_ip_count = {}
    local totals_url_count = {}
    for i = days - 1, 0, -1 do
        local t = now - i * 86400
        local date = os.date("%Y-%m-%d", t)
        local fpath = log_dir .. "/waf_" .. date .. ".log"
        local summary = _M.load_day(date, fpath, cache_dir, i > 0)
        day_cache_sizes[date] = file_size(cache_dir .. "/waf_" .. date .. ".json") or -1
        local day_obj = {
            date = date,
            found = summary.source_exists == true,
            attacks = tonumber(summary.attacks) or 0,
            whitelist_hits = tonumber(summary.whitelist_hits) or 0,
            by_method = summary.by_method or {},
            top_ips = summary.top_ips or {}
        }
        day_results[#day_results + 1] = day_obj
        totals_attacks = totals_attacks + day_obj.attacks
        for method, count in pairs(day_obj.by_method) do
            totals_by_method[method] = (totals_by_method[method] or 0) + count
        end
        for ip, count in pairs(summary.ip_counts or {}) do
            _M.merge_count(totals_ip_count, ip, count)
        end
        for url, count in pairs(summary.url_counts or {}) do
            _M.merge_count(totals_url_count, url, count)
        end
    end

    local range_summary = {
        cache_version = CACHE_VERSION,
        range_days = days,
        today = today,
        today_source_size = today_source_size,
        day_cache_sizes = day_cache_sizes,
        unit = "waf",
        days = day_results,
        totals = {
            attacks = totals_attacks,
            by_method = totals_by_method,
            top_ips = sorted_top(totals_ip_count),
            top_urls = sorted_top(totals_url_count),
            truncated = false
        }
    }
    write_cache(range_path, range_summary)
    return range_summary
end

function _M.merge_count(map, key, value)
    if not key or key == "" or not value then return end
    if map[key] ~= nil then
        map[key] = map[key] + value
        return
    end
    local count = 0
    for _ in pairs(map) do count = count + 1 end
    if count < MAX_DIMENSION_KEYS then map[key] = value end
end

function _M.top(map)
    return sorted_top(map)
end

function _M.cache_dir(log_dir)
    return log_dir .. "/.history_stats"
end

return _M
