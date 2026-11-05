-- CRASH_CLASS: SAFE (reads the VM map only; nothing is executed, no 629 mapping is created)
-- PROBE 1251a: calibrate syscall 674 as a PROT_EXEC oracle
--
-- Context: 1245a proved that an anonymous mmap with prot=7 returns a page that
-- cannot be executed (fcall faults with CS=0x43 and RIP = the page).  1248a wants
-- to use 674 (VM map query) as a NON-FATAL oracle for "did the kernel keep
-- PROT_EXEC on this mapping?" so the one fatal fcall is only spent when the
-- oracle says the page is executable.  674 has never been calibrated on 14.10:
-- no probe in this repo has ever printed one of its 72-byte records.
--
-- This probe answers three questions at once:
--   [Q1] which argument shape makes 674 return 0 with a plausible count?
--   [Q2] what is the real 72-byte record layout (start / end / prot / name)?
--   [Q3] does the recorded protection distinguish an anon prot=7 page (known NOT
--        executable) from eboot's RX .text (known executable)?
--
-- If [Q3] says the oracle cannot tell them apart, 1248a's gate is worthless and
-- 1251b is the only way forward.  Nothing here can kill the loader.

print("=== PROBE 1251a: 674 EXEC-ORACLE CALIBRATION ===")
print("")

local function N(v)
  if type(v) == "table" and v.tonumber then return v:tonumber() end
  return tonumber(v) or 0
end
local function mk(n)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = n
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function hex(v) return string.format("0x%X", v) end
local function u64(h, l) return h * 4294967296 + l end
local function bit(v, n)
  local d = 1
  for _ = 1, n do d = d * 2 end
  return math.floor(v / d) - math.floor(v / (d * 2)) * 2
end
local function bitname(p)
  local s = ""
  if bit(p, 0) == 1 then s = s .. "r" else s = s .. "-" end
  if bit(p, 1) == 1 then s = s .. "w" else s = s .. "-" end
  if bit(p, 2) == 1 then s = s .. "x" else s = s .. "-" end
  return s
end

local sc674 = mk(674)
local sc477 = mk(477)
local sc5   = mk(5)
local sc189 = mk(189)
local keep   = nil

-- [Q1] three argument shapes; the first that returns 0 with a sane count wins
local function snapshot(shape)
  local buf  = memory.alloc(72 * 512)
  local cnt  = memory.alloc(16)
  memory.write_dword(cnt, 0)
  memory.write_dword(cnt + 4, 0)
  keep = buf
  local ok, rv
  if shape == 1 then
    ok, rv = pcall(function() return sc674(uint64(N(buf)), uint64(72), uint64(512), uint64(N(cnt)), uint64(0x40000000)) end)
  elseif shape == 2 then
    ok, rv = pcall(function() return sc674(uint64(N(buf)), uint64(72), uint64(512), uint64(N(cnt)), uint64(0)) end)
  else
    ok, rv = pcall(function() return sc674(N(buf), 72, 512, N(cnt), 0) end)
  end
  if not ok then return nil, "pcall: " .. tostring(rv), 0 end
  local r = N(rv)
  local n = memory.read_dword(cnt)
  if n < 0 or n > 512 then n = 0 end
  local recs = {}
  for i = 0, n - 1 do
    local b = N(buf) + i * 72
    recs[#recs + 1] = {
      s = u64(memory.read_dword(b + 4), memory.read_dword(b)),
      e = u64(memory.read_dword(b + 12), memory.read_dword(b + 8)),
      p = memory.read_dword(b + 0x18),
      base = b,
    }
  end
  return recs, r, n
end

print("[A] argument-shape calibration")
local snap, shape_used = nil, 0
for shape = 1, 3 do
  local recs, rv, n = snapshot(shape)
  print(string.format("    shape %d -> rv=%s count=%d", shape, tostring(rv), n or 0))
  if snap == nil and recs ~= nil and #recs > 0 then
    snap, shape_used = recs, shape
  end
end
if snap == nil then
  print("    *** 674 produced no record set under any tested shape - oracle unusable ***")
  print("=== DONE 1251a ===")
  return
end
print(string.format("    using shape %d, %d regions", shape_used, #snap))

local function find_rec(addr)
  for i = 1, #snap do
    local r = snap[i]
    if addr >= r.s and addr < r.e then return r end
  end
  return nil
end

local function name_of(rec)
  if rec == nil then return "" end
  local s = ""
  for off = 0x20, 0x46 do
    local c = memory.read_byte(rec.base + off)
    if c >= 32 and c < 127 then s = s .. string.char(c) else s = s .. "." end
  end
  return s
end

local function report(label, addr)
  local r = find_rec(addr)
  if r == nil then
    print(string.format("    %-11s %s  (no 674 record covers it)", label, hex(addr)))
    return nil
  end
  print(string.format("    %-11s %s  %s - %s  prot=%s %s  name=%s",
        label, hex(addr), hex(r.s), hex(r.e), hex(r.p), bitname(r.p), name_of(r)))
  return r
end

print("")
print("[B] anon prot=3 (control: readable, must not be EXEC)")
local anon3 = nil
do
  local ok, rv = pcall(function() return sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(-1), uint64(0)) end)
  if ok then
    local v = N(rv)
    if v > 0 and v <= 0x7FFFFFFFFFFF then anon3 = v end
  end
  print(string.format("    477(anon,0x4000,prot=3) -> %s", anon3 and hex(anon3) or "FAILED"))
end

print("")
print("[C] anon prot=7 (the page 1245a proved CANNOT execute)")
local anon7 = nil
do
  local ok, rv = pcall(function() return sc477(uint64(0), uint64(0x4000), uint64(7), uint64(0x1002), uint64(-1), uint64(0)) end)
  if ok then
    local v = N(rv)
    if v > 0 and v <= 0x7FFFFFFFFFFF then anon7 = v end
  end
  print(string.format("    477(anon,0x4000,prot=7) -> %s", anon7 and hex(anon7) or "FAILED"))
  if anon7 then
    memory.write_byte(anon7, 0x90)
    print(string.format("    wrote 0x90, read back %02X", memory.read_byte(anon7)))
  end
end

print("")
print("[D] file-backed mappings of /app0/eboot.bin")
local fd = -1
do
  local ok, rv = pcall(function() return sc5("/app0/eboot.bin", 0, 0) end)
  if ok then fd = N(rv) end
  print(string.format("    open(/app0/eboot.bin) -> %d", fd))
end
local fsize = 0
if fd >= 0 then
  local st = memory.alloc(0x100)
  for i = 0, 0x3F do memory.write_dword(st + i * 4, 0) end
  local ok, rv = pcall(function() return sc189(fd, st) end)
  if ok and N(rv) == 0 then
    fsize = u64(memory.read_dword(N(st) + 0x5C), memory.read_dword(N(st) + 0x58))
    print(string.format("    fstat -> size=%s", hex(fsize)))
  else
    print(string.format("    fstat failed rv=%s", tostring(rv)))
  end
end

local file_map = {}
if fd >= 0 then
  local len = 0x4000
  if fsize > 0 and fsize < len then len = fsize end
  local prots = {1, 5, 7}
  for i = 1, 3 do
    local prot = prots[i]
    local ok, rv = pcall(function() return sc477(uint64(0), uint64(len), uint64(prot), uint64(2), uint64(fd), uint64(0)) end)
    local v = ok and N(rv) or -1
    if v > 0 and v <= 0x7FFFFFFFFFFF then
      file_map[prot] = v
      local m = memory.read_dword(v)
      print(string.format("    477(file,len=%s,prot=%d,MAP_PRIVATE) -> %s  first dword %08X", hex(len), prot, hex(v), m))
    else
      print(string.format("    477(file,len=%s,prot=%d,MAP_PRIVATE) -> FAILED rv=%s", hex(len), prot, tostring(rv)))
    end
  end
end

print("")
print("[E] the records")
local rec_anon3 = anon3 and report("anon prot3", anon3) or nil
local rec_anon7 = anon7 and report("anon prot7", anon7) or nil
local rec_f1 = file_map[1] and report("file prot1", file_map[1]) or nil
local rec_f5 = file_map[5] and report("file prot5", file_map[5]) or nil
local rec_f7 = file_map[7] and report("file prot7", file_map[7]) or nil

print("")
print("[F] positive control: eboot's own RX .text")
local eboot_text = nil
do
  local ok, rv = pcall(function() return N(eboot_base) end)
  if ok and rv and rv > 0x1000 then eboot_text = rv end
  if eboot_text == nil then
    for i = 1, #snap do
      local nm = name_of(snap[i])
      if nm:find("eboot") then eboot_text = snap[i].s end
    end
  end
  print(string.format("    eboot text candidate = %s", eboot_text and hex(eboot_text) or "unknown"))
end
local rec_etext = eboot_text and report("eboot text", eboot_text) or nil

print("")
print("[G] full 72-byte record dump (self-describing layout)")
local dump_rec = rec_f7 or rec_anon7 or rec_etext
if dump_rec then
  print(string.format("    record for %s:", hex(dump_rec.s)))
  for off = 0, 0x40, 8 do
    print(string.format("      +%02X  %08X_%08X", off,
          memory.read_dword(dump_rec.base + off + 4),
          memory.read_dword(dump_rec.base + off)))
  end
  print(string.format("      name bytes +0x20.. = %s", name_of(dump_rec)))
else
  print("    (nothing to dump)")
end

print("")
print("[H] VERDICT")
local function x(p) return p ~= nil and bit(p, 2) == 1 end
print(string.format("    anon prot7  prot=%s exec=%s   (ground truth: NOT executable, 1245a)",
      rec_anon7 and hex(rec_anon7.p) or "n/a", tostring(x(rec_anon7 and rec_anon7.p))))
print(string.format("    anon prot3  prot=%s exec=%s   (ground truth: NOT executable)",
      rec_anon3 and hex(rec_anon3.p) or "n/a", tostring(x(rec_anon3 and rec_anon3.p))))
print(string.format("    file prot7  prot=%s exec=%s   (unknown - this is the question)",
      rec_f7 and hex(rec_f7.p) or "n/a", tostring(x(rec_f7 and rec_f7.p))))
print(string.format("    eboot text  prot=%s exec=%s   (ground truth: EXECUTABLE)",
      rec_etext and hex(rec_etext.p) or "n/a", tostring(x(rec_etext and rec_etext.p))))

if rec_etext == nil then
  print("    oracle INCONCLUSIVE: no known-executable control was found in the map")
elseif x(rec_etext.p) and not x(rec_anon7 and rec_anon7.p) then
  print("    oracle USABLE: it separates a known-executable region from the known-dead anon prot7 page")
  print("    -> 1248a's gate is meaningful; if file prot7 reports exec, run 1251b")
elseif x(rec_anon7 and rec_anon7.p) then
  print("    oracle USELESS for exec: it reports PROT_EXEC on a page 1245a proved cannot execute")
  print("    -> the recorded protection is the REQUESTED protection, not the effective one")
  print("    -> skip 1248a; go straight to 1251b")
else
  print("    oracle reports no exec anywhere - check whether eboot text was really found")
end

print("")
print("=== DONE 1251a ===")
