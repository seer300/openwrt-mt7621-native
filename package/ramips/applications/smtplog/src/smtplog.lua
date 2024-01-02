#!/usr/bin/lua

-- smtplog
require "socket"
ucicore = require("uci")
smtp = require("socket.smtp")
mime = require("mime")
ltn12 = require("ltn12")

uci = ucicore.cursor()

local mailserv  = uci:get("smtplog", "test", "serverip")
local mailport  = uci:get("smtplog", "test", "serverport")
local recipient = uci:get("smtplog", "test", "recipient")
local path = "/dbg/log/dbg.log.bak"

from = "<smtplog@apsoc.dbg>"
rcpt = { recipient }

local s = socket.udp()
s:setpeername("baidu.com",80)
local wanip, _ = s:getsockname()

fp = io.open(path, "r")
if fp == nil then
    print("unable to open " .. path)
    return
else
    fp:close()
end

fp = io.open("/tmp/smtplog.sysinfo", "r")
if fp == nil then
    sysinfo = "please check the attachment"
else
    sysinfo = fp:read("*all")
    fp:close()
end

mesgt =  smtp.message{
   headers = {
      to = recipient,
      subject = "<dbg-log> sent from "..wanip
   },
   body = {
      preable = "Please check the log",
      [1] = {
         body = mime.eol(0, sysinfo)
      },
      [2] = {
         headers = {
            ["content-type"] = 'text/plain; name="dbg.log"',
            ["content-disposition"] = 'attachment; filename="dbg.log"',
            ["content-description"] = 'dbg.log',
            ["content-transfer-encoding"] = "BASE64"
         },
         body = ltn12.source.chain(
            ltn12.source.file(io.open(path, "r")),
            ltn12.filter.chain(
                mime.encode("base64"),
                mime.wrap()
                )
            )
      },
      epilogue = "..."
   }
}

r, e = smtp.send {
   from = from,
   rcpt = rcpt,
   source = mesgt,
   server = mailserv,
   port = mailport
}

if (e) then
   io.stderr:write("Could not send email: ", e, "\n")
end
