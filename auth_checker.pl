#!/usr/bin/perl
# auth_checker.pl      License: GPLv2
# Ivo Truxa  (c) 2014  <truxa@truxoft.com>
# (based on the script detect_hacked_smtp_auth_conns.pl  by Todd Lyons)

# ------- VERSION -----------------------------------------------------
my $version = "2.03";
my $verdate = "2014-02-13";

# ------- CONFIGURATION -----------------------------------------------
# These parameter can be modified to match the respective system
my $geoip_db_path     = '/usr/local/share/GeoIP';
my $ignored_countries = 'CZ|FR';
my @ignored_users     = qw//;
my @ignored_ips       = qw/^127.0.0.1$ ^89.2\.152.32$ ^82.67.20\.20$ ^88.100.17\.83$ ^90.183.165.12[2|4]$ ^90.183.21\.94$ ^90.182.9\.41$ ^194.228.149.244$ ^89.177.86.166$/;
my %log_files         = (
        'exim'        => '/var/log/exim/mainlog*',
        'dovecot'     => '/var/log/maillog*',
        'ssh'         => '/var/log/auth.log*',
        'openwm'      => '/var/log/openwebmail.log*',
        'apache'      => '/var/log/httpd/access.log*',
        'courier'     => '/var/log/mail.info*',
        'all'         => 'default log files'
);
push(@ignored_ips, &ignore_ISPs);

# ------ PURPOSE ------------------------------------------------------
# The purpose of the script is the detection of user accounts accessed
# in unusual patterns - either from countries not on the whitelist, or
# from not explicitely whitelisted IP addresses, or from a higher number
# of IP addresses than specified. In other words, it can help detecting
# compromised accounts already being abused.
#
# Currently, Exim SMTP, Dovecot POP3, IMAP, SSH, Apache, and Openwebmail
# authentications are supported.
#
# This utility was NOT designed fordetecting intrusion attempts. There
# are already plenty of intrusion detection programs. This script was
# designed to detect already compromised accounts, that (in contrary)
# intrusion detection usually does not detect.
# ---------------------------------------------------------------------

my $u1 = "\nauth_checker.pl  STMP/POP3 Authentication Abuse Detection Utility v".$version." (".$verdate.")  \n".
         "  Written by Ivo Truxa (c) 2014 <truxa\@truxoft.com>                                   \n".
         "  (based on the script detect_smtp_auth_abuse.pl  by Todd Lyon (c) 2013)               \n";
my $u2 = "  usage: detect_auth_abuse.pl [options...] [logfile]                                   \n".
         "     Otions:                                                                           \n".
         "        -l, --limit N     Print accounts accessed from N or more IP adresses           \n".
         "                          default 0;   exceptions defined in the script not counted    \n".
         "                          uness limit is less than 0 (exceptions will be counted too)  \n".
         "        -q, --quiet       shows no output when no matching IP address found            \n".
         "        -m, --mode <name> set to exim, dovecot, ssh, courier, or apache mode (default exim)\n".
         "                          set to  all  to parse default log files of all modes         \n".
         "        -u, --user <name> list all IP addresses of given user                          \n".
         "        --nodate          Do not group the access data by date                         \n".
         "        --nouser          Do not group the IP addresses data by user, list them all    \n".
         "        --nopass          Do not reset passwords (automated passwords resetting must   \n".
         "                          be defined within the script, otherwise no reset is done)    \n".
         "        -g, --geoip N     GeoIP mode - 2 (full - default), 1 (short), 0 (none)         \n".
         "        -d, --debug       display debug output                                         \n".
         "        -c, --changelog   display version history and exit                             \n".
         "        -v, --version     display version number and exit                              \n".
         "        -h, --help        showing this information                                     \n\n".
         "     logfile              by default '/var/log/exim/mainlog' for mode exim,            \n".
         "                          '/var/log/maillog' for mode dovecot,                         \n".
         "                          '/var/log/auth' for mode ssh, and                            \n".
         "                          '/var/log/mail.info' for mode courier, and                   \n".
         "                          '/var/log/httpd/access.log' for mode apache                  \n";
my $changelog =
" 2.03 [Ivo Truxa] 02/13/2014                                                                    \n".
"       - IO::Uncompress::AnyUncompress added for better compressed file support (conditional)   \n".
"       - added wildcards support - log file names can now include wildcards                     \n".
"       - default log file names changed to contain wildcards now                                \n".
"       - added listung of all parsed log files to the report header                             \n".
" 2.02 [Ivo Truxa] 02/13/2014                                                                    \n".
"       - negative --limit now bypasses the exception checking - all access IPs will be counted  \n".
"         and the absolute value of the limit option will be used as the trigger                 \n".
"       - added option --nodate for suppressing grouping of results by date                      \n".
"       - added option --nouser for suppressing grouping of results by user                      \n".
"       - when option --mode is set to 'all', default log files in all mode will be parsed       \n".
"       - added usage info on wrong usage and with the -h, --help switches                       \n".
"       - soft handling of missing log files instead of abort (importan in the 'all' mode)       \n".
"       - Geo::IP class now added and used with priority over Geo::IP::PurePerl                  \n".
"       - Geo::IP** and  IO::Uncompress** modules now loaded conditionally when/if needed,       \n".
"         the script will run even without the module, just with limited functinality            \n".
" 2.01 [Ivo Truxa] 02/12/2014                                                                    \n".
"       - added usage info on wrong usage and with the -h, --help switches                       \n".
"       - added this version history  info with the --changelog switch                           \n".
"       - added variables \$version and \$verdate                                                \n".
"       - added a hash with regex patterns for parsing Exim and Dovecot logs                     \n".
"       - added handling the mode switch for Dovecot and Exim modes                              \n".
"       - predefined IP blocks of cellular networks loaded in dependence of \$ignored_countries  \n".
"       - added switch --user for displaying all IP addresses of the given user name             \n".
"       - reading of gzipped and bzipped log files now possible directly                         \n".
"       - added parsing of SSH logs (auth)                                                       \n".
"       - added parsing of openwebmail logs (auth)                                               \n".
"       - added parsing of apache logs (auth)                                                    \n".
"       - added ISP name for each IP address (if found by GeoIP)                                 \n".
"       - added option --quiet for suppressing output when no suspicious IP address found        \n".
"       - --limit can be now set to 0, and this is now the default value (showing all)           \n".
"       - output formatted into fixed width columns                                              \n".
" 2.00 [Ivo Truxa] 02/10/2014                                                                    \n".
"       - added dovecot_plain and dovecot_login authentication type to the Exim log detection    \n".
"       - cosmetic changes in the output, reordering/reformatting of rows and columns            \n".
"       - GeoIP localization of all authenticated IP addresses and reporting when accounts       \n".
"         accessed from countries no on the allowed list.                                        \n".
"       - logging temporarily disabled                                                           \n".
" 1.xx [Todd Lyon] 2013   https://github.com/Exim/exim/wiki/DetectSMTPAuthAbuse                  \n";

use strict;
use warnings;
use Getopt::Long;

$|=1;

# -----------------------------------------------------------------------
sub myend($) {print shift(),"\n"; exit 0;}
# -----------------------------------------------------------------------
my %opts;
GetOptions( \%opts, 'debug', 'limit:i', 'nopass', 'mode:s', 'user:s', 'geoip:i', 'version', 'help', 'changelog', 'quiet', 'nodate', 'nouser');
$opts{'help'}      and myend("$u1  \n$u2  \n");
$opts{'changelog'} and myend("$u1  \n$changelog  \n");
$opts{'version'}   and myend("auth_checker v$version ($verdate)  \n");
$opts{'limit'} = ( defined $opts{'limit'} )? $opts{'limit'} : 0;
$opts{'geoip'} = ( defined $opts{'geoip'} && $opts{'geoip'}>=0 )? $opts{'geoip'} : 2;
$opts{'mode'}  = ( defined $opts{'mode'}  && $opts{'mode'}=~/all|exim|dovecot|ssh|openwm|apache|courier/ )? $opts{'mode'} : 'exim';
# -----------------------------------------------------------------------

# Sample log lines:
# EXIM:         2014-02-11 07:03:11 1WD6R5-000DJZ-Lc <= usernm@domain.com H=host.remote.com (HeloName) [99.111.22.33] P=esmtpsa X=TLSv1:AES128-SHA:128 A=dovecot_login:usernm S=3328 id=001201cf26ee$f1c31680$d5494380$@cz
# DOVECOT:      Feb 11 16:49:22 myhost dovecot: pop3-login: Login: user=<usernm>, method=PLAIN, rip=11.222.33.44, lip=11.0.222.33, mpid=91587, session=<0LRqZiPyAwAlvORG>
# SSH:          Jan 19 00:01:51 myhost sshd[40547]: Accepted keyboard-interactive/pam for somename from 55.66.77.88 port 2955 ssh2
# OpenWebMail:  Fri Feb  7 20:05:36 2014 - [33236] (11.222.33.44) info - login - info@doman.com*webmail.domain.com-session-0.247656818802596 - active=0,0,0
# APACHE:       111.222.33.44 - username [12/Feb/2014:20:20:34 +0100] "GET /path/page.htm HTTP/1.1" 200 1794"
# COURIER:      Nov 16 01:33:25 mail pop3d-ssl: LOGIN, user=usernm, ip=[::ffff:11.222.33.44], port=[50111]

my @modes         = ('exim','dovecot','ssh','openwm','courier');
my %log_vars      = (
        'exim'    => '$date, $time, $ip,   $type, $auth, $user',
        'dovecot' => '$date, $time, $auth, $user, $ip',
        'ssh'     => '$date, $time, $auth, $user, $ip',
        'openwm'  => '$date, $time, $ip,   $user',
        'apache'  => '$ip,   $user, $date, $time',
        'courier' => '$date, $time, $auth, $user, $ip'
);
my %log_pattern   = (
        'exim'    => '^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}).*H=.*\[(\d+\.\d+\.\d+\.\d+)\].*A=(?:(dovecot_)?(plain|login)):([^ ]+)',
        'dovecot' => '^(\w{3} .\d) (\d{2}:\d{2}:\d{2}) \w+ dovecot: (pop3|imap)-login: Login: user=\<(.*)\>,.+ rip=(\d+\.\d+\.\d+\.\d+), ',
        'ssh'     => '^(\w{3} .\d) (\d{2}:\d{2}:\d{2}) \w+ sshd\[\d+\]: Accepted (\S+) for (\w+) from (\d+\.\d+\.\d+\.\d+) port \d+ ssh.\s*$',
        'openwm'  => '^\w{3} (\w{3} .\d) (\d{2}:\d{2}:\d{2}) \d{4} - \[\d+\] \((\d+\.\d+\.\d+\.\d+)\) (\w+) - login - ',
        'apache'  => '^(\d+\.\d+\.\d+\.\d+) - (\w+) \[(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2}) [+-]\d+\] ',
        'courier' => '^(\w{3} .\d) (\d{2}:\d{2}:\d{2}) \w+ (pop3d-ssl|pop3d|imapd|imapd-ssl): LOGIN, user=(\w+), ip=\[::ffff:(\d+\.\d+\.\d+\.\d+)\],'
);
if ( !($opts{'mode'} =~ /all/) ) {
    @modes = ($opts{'mode'});
}

my ($fh, $found, $geoip1, $geoip2, $geoip_pure);
my $header  = "\nReport of Authenticated Access by Unknown IP Addresses:\n";

if ($opts{'geoip'}) {
    require Geo::IP;
    $geoip1     = Geo::IP->open(          "$geoip_db_path/GeoLiteCity.dat");
    $geoip2     = Geo::IP->open(          "$geoip_db_path/GeoIPASNum.dat");
    $geoip_pure = 0;
    if ($@) {
        require Geo::IP::PurePerl;
        $geoip1 = Geo::IP::PurePerl->open("$geoip_db_path/GeoLiteCity.dat");
        $geoip2 = Geo::IP::PurePerl->open("$geoip_db_path/GeoIPASNum.dat");
        $geoip_pure = 1;
    }
    if ($@) {
        undef $geoip_pure;
        $header .= "\n\n   -- please install the Geo-IP or Geo-IP-PurePerl modules".
                     "\n   -- to see the country, city, and the owner of each IP addr.\n";
    }
}

foreach my $mode (@modes) {

  my @files = (@ARGV)? @ARGV : glob($log_files{$mode});
  for my $file (@files) {
    $header .= "    ". uc($mode) .": $file \n";
    next unless ($fh = &get_handle($file));

    while (<$fh>) {
	my $foreign = 0;
	my ($date,$time,$ip,$type,$auth,$user);
	if ( $_ =~ /$log_pattern{$mode}/ ) {
	    eval("( $log_vars{$mode} ) = (\$1,\$2,\$3,\$4,\$5,\$6)");
	    if ( !defined $opts{'user'} && $opts{'limit'}>=0 ) {
		next if ( grep {/^$user$/}   @ignored_users );
		next if ( grep {$ip =~ /$_/} @ignored_ips );
	    }
	    my $country_id;
	    if (defined $opts{'geoip'} && $opts{'geoip'}) {
		if ($geoip_pure) {
		    ($country_id) = $geoip1->get_city_record($ip);
		} else {
		    my $rec = $geoip1->record_by_addr($ip);
		    $country_id = $rec->country_code;
		}
	    }
	    if (defined $opts{'nodate'}) {$date = 'all dates';}
	    if (defined $opts{'nouser'}) {$user = 'all users';}
	    if (defined $country_id) {
		$foreign = 0 + !($country_id =~ /$ignored_countries/);
	    }
	    $found->{$date}->{$user}->{'ip'}->{$ip}++;
	    $found->{$date}->{$user}->{'lasttime'} = $time;
	    $found->{$date}->{$user}->{'lastip'}   = $ip;
	    $found->{$date}->{$user}->{'foreign'}  = $foreign;
	}
    }
  }
};

for my $date  (sort keys %$found) {
  (my $logdir = "/tmp/".$date) =~ s/ /_/g;
  my $f = $found->{$date};
  for my $user (sort keys %$f) {
    if (    (defined $opts{'user'} && ($user =~ $opts{'user'})) ||
            !defined $opts{'user'} && (
                defined $opts{'debug'}    ||
                $f->{$user}->{'foreign'} ||
                ( scalar (keys %{$f->{$user}->{'ip'}}) >= abs($opts{'limit'}) )
            )
        ) {
        # Make the directory IFF found something to log
#       mkdir $logdir if ( ! -d $logdir && ! $opts{'debug'});
#       my $logfile = "$logdir/$user";
#       if (!$opts{'debug'}) {
#           next if ( -f $logfile );
#           open(F,'>',$logfile) && close(F);
#       }
        if (defined $header) {print $header; undef $header;}
        print "\n$date -> account $user: ", scalar keys %{$f->{$user}->{'ip'}}, " IPs (Last: $f->{$user}->{'lastip'} \@ $f->{$user}->{'lasttime'})\n";
        print map {
            my $ip = $_;
            my ($country, $city, $isp, $c2, $c3, $r);
            $country = $city = $isp = '';
            if (defined $geoip1 && defined $geoip2 && defined $opts{'geoip'} && $opts{'geoip'}) {
                if ($geoip_pure) {
                    ($c2,$c3,$country,$r,$city) = $geoip1->get_city_record($ip);
                    $isp         = $geoip2->isp_by_addr($ip);
                } else {
                    $r           = $geoip1->record_by_addr($ip);
                    $isp         = $geoip2->org_by_addr($ip);
                    $c2          = $r->country_code;
                    $country     = $r->country_name;
                    $city        = $r->city;
                }
                if ($opts{'geoip'} == 1) {$country = $c2;}
            }
            $isp =~ s/AS\d+ //;
            "   ".
            substr( $f->{$user}->{'ip'}->{$ip} ."       ", 0,  6 ).
            substr( $ip                        ."       ", 0, 18 ).
            substr( ($country||'') . (($city)? ", $city" : '') . (($isp)? " - $isp" : ''), 0, 50 ).
            "\n"
        }  sort keys %{$f->{$user}->{'ip'}};
        next if ($opts{'debug'});
        &reset_password($user) unless($opts{'nopass'});
        print &create_admin_alert($f,$user);
    }
  }
}
if (defined $header) {
    if (defined($opts{'quiet'}))
         {{exit 0;}}
    else {myend("$header   No matching authentications found!\n");}
} else   {myend('');}


# -----------------------------------------------------------------------
sub get_handle{
# -----------------------------------------------------------------------
  my $fh   = *STDIN;
  my $err  = "Opening logfile:";
  my $file = shift;

  if (defined $file) {
    require IO::Uncompress::AnyUncompress;
    if ( ($fh = IO::Uncompress::AnyUncompress->new($file)) ) {
    } else {
	if ($file =~ /.+\.bz2$/) {
	    require IO::Uncompress::Bunzip2;
	    if (! ($fh = IO::Uncompress::Bunzip2->new($file)) ) {$header .= "\n$err $!\n";}
	} elsif ($file =~ /.+\.gz$/) {
	    require IO::Uncompress::Gunzip;
	    if ( !($fh = IO::Uncompress::Gunzip->new($file)) )  {$header .= "\n$err $!\n";}
	}  else {
	    if ( !open($fh,'<', $file) )                        {$header .= "\n$err $!\n";}
	}
    }
  }
  return $fh;
}


# Randomly blocking accounts is a good way to run off customers.  Send a
# message to yourself, and maybe the customer or their boss about what was
# found and why the mailbox "stopped working".
# -----------------------------------------------------------------------
sub create_admin_alert{
# -----------------------------------------------------------------------
  my $f     = shift()                             or return "Unable to access data from logs\n";
  my $email = shift()                             or return "Unable to determine mailbox for alert\n";
  my $count = scalar keys %{$f->{$email}->{'ip'}} or return "Unable to create alert, can't determine count for mailbox $email\n";
  my $response = "";
  # Do something here to create an alert that a hacked account was detected
  return ($response);
}


# Resetting the password will cause the smtp auth abuse to stop, but it
# will not lock the user's mailbox so it will continue to deliver
# inbound email.
# -----------------------------------------------------------------------
sub reset_password{
# -----------------------------------------------------------------------
  my $email = shift() or return;
  # Do something here to reset password
}


# Certain wireless carriers seem to make devices switch IP's as they
# move from tower to tower. Just ignore those problem ranges.
# Note by Ivo Truxa: keep only the networks your users really need,
# so if they are not US based, replace the IP blocks with local ones
# -----------------------------------------------------------------------
sub ignore_ISPs {
# -----------------------------------------------------------------------
  my @i;
  push(@i, qw/^207.46.8\.22[0-2] ^65.55.41.1/);                                 # email forwarders: Microsoft / Hotmail
  push(@i, qw/^209.85.16[01]. ^209.85.21[2-6]. ^209.85.220\. ^74.125.82./);     # email forwarders: Google / Gmail
  if ('US' =~ /$ignored_countries/) {                                           # US cellular networks
    push(@i, qw/^50.29. ^174.2\d\d\. ^174.19[2-9]/);                            # VZ Wireless
    push(@i, qw/^198.228.19[678]/);                                             # Cingular Wireless
    push(@i, qw/^208.54.36./);                                                  # TMobile (tmodns.net)
  }
  if ('CZ' =~ /$ignored_countries/) {                                           # Czech cellular networks
    push(@i, qw/^37.188.2/);                                                    # Eurotel
    push(@i, qw/^46.135./);                                                     # Vodafone
    push(@i, qw/^89.24\.108.174/);                                              # T-Mobile
  }
  if ('FR' =~ /$ignored_countries/) {                                           # French cellular networks
    push(@i, qw/^193.253.[12]\d\d\./);                                          # Orange
    push(@i, qw/^195.132.2\d\d\./);                                             # Numericable
  }
  return(@i);
}
