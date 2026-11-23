-- Samsung Galaxy S10+ (beyond2lte): echo reference for the call microphone.
--
-- Links the Speaker sink monitor to the echo reference stream of
-- beyond2lte.call-mic only while that source is running (an app records from
-- it), and removes the links when it goes idle. A permanent (even paused,
-- passive) link would put the internal mic and the playback PCM into one
-- driver group whenever both are in use for unrelated things, which on this
-- hardware (1024-frame ALSA periods) caused xruns and resyncs on both.

local log = Log.open_topic("s-beyond2lte-call-mic")

local SRC  = "beyond2lte.call-mic"
local REF  = "beyond2lte.call-mic.reference"
local SINK = "alsa_output.platform-sound.HiFi__Speaker__sink"

local links = {}
local wanted = false

local nodes_om = ObjectManager {
  Interest { type = "node", Constraint { "node.name", "c", SRC, REF, SINK } }
}
local ports_om = ObjectManager {
  Interest { type = "port" }
}

local function find_node(name)
  return nodes_om:lookup { Constraint { "node.name", "=", name } }
end

local function unlink()
  for _, l in ipairs(links) do
    pcall(function() l:request_destroy() end)
  end
  if #links > 0 then
    log:info("echo reference unlinked")
  end
  links = {}
end

local function link()
  if #links > 0 then return end
  local sink, ref = find_node(SINK), find_node(REF)
  if not sink or not ref then return end
  local sid, rid = sink["bound-id"], ref["bound-id"]
  local inports = {}
  for p in ports_om:iterate { Constraint { "node.id", "=", tostring(rid) },
                              Constraint { "port.direction", "=", "in" } } do
    table.insert(inports, p)
  end
  if #inports == 0 then return end
  for p in ports_om:iterate { Constraint { "node.id", "=", tostring(sid) },
                              Constraint { "port.direction", "=", "out" },
                              Constraint { "port.monitor", "=", "true" } } do
    for _, ip in ipairs(inports) do
      local l = Link("link-factory", {
        ["link.output.node"] = tostring(sid),
        ["link.output.port"] = tostring(p["bound-id"]),
        ["link.input.node"]  = tostring(rid),
        ["link.input.port"]  = tostring(ip["bound-id"]),
        ["object.linger"]    = "false",
      })
      l:activate(Feature.Proxy.BOUND, function(_, err)
        if err then log:warning("link failed: " .. tostring(err)) end
      end)
      table.insert(links, l)
    end
  end
  log:info("echo reference linked (" .. #links .. " links)")
end

local function update()
  local src = find_node(SRC)
  local running = src ~= nil and src.state == "running"
  if running and not wanted then
    wanted = true
    link()
  elseif not running and wanted then
    wanted = false
    unlink()
  elseif running and #links == 0 then
    link()
  end
end

nodes_om:connect("object-added", function(_, node)
  node:connect("state-changed", function() update() end)
  update()
end)
nodes_om:connect("object-removed", function(_, node)
  local n = node.properties["node.name"]
  if n == SINK or n == REF then
    links = {}
  end
  update()
end)
ports_om:connect("object-added", function()
  if wanted and #links == 0 then link() end
end)

nodes_om:activate()
ports_om:activate()
