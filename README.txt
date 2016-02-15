= README
  

== Description 
   This light-weight daemon program will send continuous poisoned arp packets to the 
   target.  The packets contains the fake matching pair of MAC and IP.
   For example, the MAC address of attacker's sniffer and target's 
   internet gateway IP. Thus the target host would be confused to send 
   information destinated for internet to attacker's sniffer mac 
   address instead. A classic example of the Man-in-the-middle attacking tool.  

== Install
   The program is depending on the following PERL modules:
	use Proc::PID::File;
	use POSIX qw(setsid);
	use Log::Dispatch;
	use Log::Dispatch::File;
	use Date::Format;
	use File::Spec;
	use Net::ARP;
	use Net::Ping;
   You'll need to install the above modules in your Perl environment before using it. The simplest
   way of install a Perl module is by using CPAN: 
     $ perl -MCPAN -e shell
	...
     cpan> install Proc::PID::File
	...
  
 
== Credit
   Developed by, Yang Li			
   Test in Fedora 11 Linux environment; for other *nix variance, the code
   may need to be customized to run in the daemon mode. 
      
   --  Inspired by Dug Song's famous DSNIFF package  
