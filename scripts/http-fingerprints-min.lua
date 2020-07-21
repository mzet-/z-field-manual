local io = require "io"
local string = require "string"
local table = require "table"

fingerprints = {};

local stdnse = require "stdnse"
local nmap = require "nmap"

nikto_db_path = stdnse.get_script_args("http-fingerprints.nikto-db-path") or "db_tests"
local f = nmap.fetchfile(nikto_db_path) or io.open(nikto_db_path, "r")

if f then

  stdnse.debug1("Found nikto db.")

  local nikto_db = {}
  for l in io.lines(nikto_db_path) do

    -- Skip comments.
    if not string.match(l, "^#.*") then

      record = {}

      for field in string.gmatch(l, "\"(.-)\",") do

        -- Grab every attribute and create a record.
        if field then
          string.gsub(field, '%%', '%%%%')
          table.insert(record, field)
        end
      end

      -- Make sure this record doesn't exists already.
      local exists = false
      for _, f in pairs(fingerprints) do
        if f.probes then
          for __, p in pairs(f.probes) do
            if p.path then
              if p.path == record[4] then
                exists = true
                break
              end
            end
          end
        end
      end

      -- What we have right now, is the following record:
      -- record[1]: Nikto test ID
      -- record[2]: OSVDB-ID
      -- record[3]: Server Type
      -- record[4]: URI
      -- record[5]: HTTP Method
      -- record[6]: Match 1
      -- record[7]: Match 1 (Or)
      -- record[8]: Match1 (And)
      -- record[9]: Fail 1
      -- record[10]: Fail 2
      -- record[11]: Summary
      -- record[12]: HTTP Data
      -- record[13]: Headers

      -- Is this a valid record?  Atm, with our current format we need
      -- to skip some nikto records. See NSEDoc for more info.

      if not exists
        and record[4]
        and record[8] == "" and record[10] == "" and record[12] == ""
        and (tonumber(record[4]) == nil or (tonumber(record[4]) and record[4] == "200")) then

        -- Our current format does not support HTTP code matching.
        if record[6] == "200" then record[6] = "" end

        nikto_fingerprint = { category = "nikto",
        probes = {
          {
            path = record[4],
            method = record[5]
          }
        },
        matches = {
          {
            dontmatch = record[9],
            match = record[6],
            output = record[11]
          },
        },
      }

      -- If there is a second match, add it.
      if record[7] and record[7] ~= "" then
        table.insert(nikto_fingerprint.matches, { match = record[7], output = record[11] })
      end

      table.insert(fingerprints, nikto_fingerprint)

    end
  end
end
end
