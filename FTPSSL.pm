# File    : Net::FTPSSL
# Author  : kral <kral at paranici dot org>
# Created : 01 March 2005
# Version : 0.06
# Revision: $Id: FTPSSL.pm,v 1.24 2005/10/23 14:37:12 kral Exp $

package Net::FTPSSL;

use strict;
use warnings;
use vars qw( $VERSION @EXPORT );
use base ( 'Exporter', 'IO::Socket::SSL' );
use IO::Socket::INET;
use Net::SSLeay::Handle;
use Carp qw( carp croak );
use Errno qw/ EINTR /;

$VERSION = "0.06";
@EXPORT  = qw( IMP_CRYPT EXP_CRYPT );

# Command Chanel Protection Levels
use constant IMP_CRYPT => "I";
use constant EXP_CRYPT => "E";

# Data Channel Protection Levels
use constant DATA_PROT_CLEAR        => "C";
use constant DATA_PROT_SAFE         => "S";
use constant DATA_PROT_CONFIDENTIAL => "E";
use constant DATA_PROT_PRIVATE      => "P";   # Default & most secure!

# Valid FTP Result codes
use constant CMD_INFO    => 1;
use constant CMD_OK      => 2;
use constant CMD_MORE    => 3;
use constant CMD_REJECT  => 4;
use constant CMD_ERROR   => 5;
use constant CMD_PROTECT => 6;
use constant CMD_PENDING => 0;
use constant MODE_BINARY => "I";
use constant MODE_ASCII  => "A";

use constant TRACE_MOD => 5;   # How many iterations between ".".  Must be >= 2.

sub new {
  my $self         = shift;
  my $type         = ref($self) || $self;
  my $host         = shift;
  my %arg          = @_;

  my $encrypt_mode = $arg{Encryption} || EXP_CRYPT;
  my $port         = $arg{Port} || ($encrypt_mode eq EXP_CRYPT ? 'ftp(21)' : 990);
  my $debug        = $arg{Debug} || 0;
  my $timeout      = $arg{Timeout} || 120;
  my $buf_size     = $arg{Buffer} || 10240;
  my $trace        = $arg{Trace} || 0;
  my $data_prot    = $arg{DataProtLevel} || DATA_PROT_PRIVATE;
  my $use_ssl      = $arg{useSSL};

  croak "Host undefined" unless $host;

  croak "Encryption mode unknown!  ($encrypt_mode)"
    if ( $encrypt_mode ne IMP_CRYPT && $encrypt_mode ne EXP_CRYPT );

  croak "Data Channel mode unknown! ($data_prot)"
    if ( $data_prot ne DATA_PROT_CLEAR &&
         $data_prot ne DATA_PROT_SAFE &&
         $data_prot ne DATA_PROT_CONFIDENTIAL &&
         $data_prot ne DATA_PROT_PRIVATE );

  # We start with a clear connection, 'cause I don't know if the
  # connection will be implicit or explicit.
  my $socket = IO::Socket::INET->new(
                         PeerAddr => $host,
                         PeerPort => $port,
                         Proto    => 'tcp',
                         Timeout  => $timeout
                         )
                   or return undef;

  $socket->autoflush(1);
  ${*$socket}{'debug'} = $debug;
  return undef unless ( response($socket) == CMD_OK );

  # In explicit mode, FTPSSL send an AUTH SSL command, catch the messages
  # and then transform the clear connection in a crypted one.
  if ( $encrypt_mode eq EXP_CRYPT ) {
    command( $socket, "AUTH", ($use_ssl ? "SSL" : "TLS" ) );
    return undef unless ( response($socket) == CMD_OK );
  }

  # Turn the clear connection in a SSL one.
  my $mode = $use_ssl ? "SSLv23" : "TLSv1";
  my $obj = $type->start_SSL( $socket, SSL_version => $mode )
               or croak ( "$mode:  " . IO::Socket::SSL::errstr () );

  # This is made for catch the banner when the connection
  # is implicitly crypted.
  # if ( $encrypt_mode eq IMP_CRYPT ) {
  #   return undef unless ( response($socket) == CMD_OK );
  # }

  ${*$obj}{'debug'}     = $debug;
  ${*$obj}{'timeout'}   = $timeout;
  ${*$obj}{'buf_size'}  = $buf_size;
  ${*$obj}{'type'}      = MODE_ASCII;
  ${*$obj}{'trace'}     = $trace;
  ${*$obj}{'data_prot'} = $data_prot;

  return $obj;
}

#-----------------------------------------------------------------------
# TODO:
# - Adding ACCT (Account) support (response 332 on password)
sub login {
  my $self = shift;
  my ( $user, $pass ) = @_;

  return 0 unless $self->user($user);

  return 0 unless $self->password($pass);
  return 1;
}

#-----------------------------------------------------------------------

sub user {
  my ( $self, $user ) = @_;
  my $resp = $self->_user($user);
  unless ( $resp == CMD_OK || $resp == CMD_MORE ) { return 0; }
  return 1;
}

sub password {
  my ( $self, $pass ) = @_;
  my $resp = $self->_passwd($pass);
  unless ( $resp == CMD_OK || $resp == CMD_MORE ) { return 0; }
  return 1;
}

sub quit {
  my $self = shift;
  $self->_quit() or return 0;
  $self->close();
  return 1;
}

sub pasv {
  my $self = shift;

  $self->_pbsz();
  unless ($self->_prot()) { return 0; }

  $self->command("PASV");

  # my $msg = $self->getline();
  # print STDERR "<<< " . $msg if ${*$self}{'debug'};
  # unless ( substr( $msg, 0, 1 ) == CMD_OK ) { return 0; }

  unless ( $self->response () == CMD_OK ) { return 0; }
  my $msg = $self->last_message ();

  $msg =~ m/(\d+)\s(.*)\(((\d+,?)+)\)\.?/
    ;    # [227] [Entering Passive Mode] ([h1,h2,h3,h4,p1,p2]).

  my @address = split( /,/, $3 );

  my $host = join( '.', @address[ 0 .. 3 ] );
  my $port = $address[4] * 256 + $address[5];

  my $socket;
  if ( ${*$self}{'data_prot'} eq DATA_PROT_PRIVATE ) {
     $socket = Net::SSLeay::Handle->make_socket( $host, $port )
               or croak "Can't open secure data connection to $host:$port";

  } elsif ( ${*$self}{'data_prot'} eq DATA_PROT_CLEAR ) {
     $socket = IO::Socket::INET->new( PeerAddr => $host, PeerPort => $port,
                                      Proto => 'tcp',
                                      Timeout => ${*$self}{'timeout'} )
               or croak "Can't open clear data connection to $host:$port";

  } else {
     # DATA_PROT_SAFE
     # DATA_PROT_CONFIDENTIAL
     croak "Currently doesn't support mode ${*$self}{'data_prot'} for data channels.";
  }

  unless ($socket) { croak "Can't open $host:$port"; }

  ${*$self}{'data_ch'} = \*$socket;

  return 1;
}

sub _get_data_channel {
   my $self = shift;

   my $io;
   if ( ${*$self}{'data_prot'} eq DATA_PROT_PRIVATE ) {
      $io = IO::Handle->new ();
      tie ( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

   } elsif ( ${*$self}{'data_prot'} eq DATA_PROT_CLEAR ) {
      $io = ${*$self}{'data_ch'};

   } else {
      # DATA_PROT_SAFE
      # DATA_PROT_CONFIDENTIAL
      croak "Currently doesn't support mode ${*$self}{'data_prot'} for data channels.";
   }

   $io->autoflush (1);

   return ( $io );
}

sub list {
  my $self = shift;
  my $path = shift;
  my $dati;

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( $self->_list($path) ) {
    my ( $tmp, $io, $size );

    $size = ${*$self}{'buf_size'};

    $io = $self->_get_data_channel ();

    while ( my $len = sysread $io, $tmp, $size ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on read while list(): $!\n";
      }
      $dati .= $tmp;
    }

    $io->close();
  }

  $self->response;    # For catch "226 Closing data connection."

  return $dati ? split( /\015\012/, $dati ) : ();
}

sub nlst {
  my $self = shift;
  my $path = shift;
  my $dati;

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( $self->_nlst($path) ) {
    my ( $tmp, $io, $size );

    $size = ${*$self}{'buf_size'};

    $io = $self->_get_data_channel ();

    while ( my $len = sysread $io, $tmp, $size ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on read while nlst(): $!\n";
      }
      $dati .= $tmp;
    }
    $io->close();
  }

  $self->response;    # For catch "226 Closing data connection."

  return $dati ? split( /\015\012/, $dati ) : ();
}

sub get {
  my $self     = shift;
  my $file_rem = shift;
  my $file_loc = shift;
  my ( $size, $localfd );
  my $close_file = 0;

  unless ($file_loc) {
    require File::Basename;
    $file_loc = File::Basename::basename($file_rem);
  }

  $size = ${*$self}{'buf_size'} || 2048;

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!";
  }

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;
  }
  else {
    unless ( open( $localfd, "> $file_loc" ) ) {
      $self->_abort();
      croak "Can't create local file!";
    }
    $close_file = 1;
  }

  # my $fix_cr_issue = ($^O !~ m/MSWin[0-9]+$/);
  my $fix_cr_issue = 1;
  if ( ${*$self}{'type'} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
    $fix_cr_issue = 0;
  }

  if ( $self->_retr($file_rem) ) {
    my ( $data, $written, $io );

    $io = $self->_get_data_channel ();

    print STDERR "get() trace ."  if (${*$self}{'trace'});
    my $cnt = 0;
    my $prev = "";

    while ( ( my $len = sysread $io, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on get(): $!\n";
      }

      if ( $fix_cr_issue ) {
         # What if this line was truncated? (Ends with \015 instead of \015\012)
         if ( $data =~ m/^(.*)(\015)$/ ) {
            $data = $prev . $1;
            $prev = $2;

         # What if the previous line was truncated?
         } elsif ( $prev ne "" ) {
            $data = $prev . $data;
            $prev = "";
         }

         $data =~ s/\015\012/\n/g;
         $len = length ($data);
      }

      print STDERR "."  if (${*$self}{'trace'} && ($cnt % TRACE_MOD) == 0);
      ++$cnt;

      $written = syswrite $localfd, $data, $len;
      croak "System write error on get(): $!\n" unless defined $written;
    }

    # Potentially write a last ASCII char to the file ...
    if ($prev ne "") {
      $written = syswrite $localfd, $prev, length ($prev);
      croak "System write error on get(): $!\n" unless defined $written;
    }

    print STDERR ". done!\n"  if (${*$self}{'trace'});

    close ($localfd)  if ($close_file);
    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;
  }

  close ($localfd)  if ($close_file);

  return undef;
}

sub put {
  my $self     = shift;
  my $file_loc = shift;
  my $file_rem = shift;
  my ( $size, $localfd );
  my $close_file = 0;

  $size = ${*$self}{'buf_size'} || 2048;

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;
    croak "If you had passed a stream, you must specify the remote filename."
      unless $file_rem;
  }
  else {
    unless ( open( $localfd, "< $file_loc" ) ) {
      $self->_abort();
      croak "Can't open local file!";
    }
    $close_file = 1;
  }

  unless ($file_rem) {
    require File::Basename;
    $file_rem = File::Basename::basename($file_loc);
  }

  my $fix_cr_issue = 1;
  if ( ${*$self}{'type'} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
    $fix_cr_issue = 0;
  }

  # If alloc_size is already set, I skip this part
  unless ( defined ${*$self}{'alloc_size'} ) {
    if ( -f $file_loc ) {
      my $size = -s $file_loc;
      $self->alloc($size);
    }
  }

  delete ${*$self}{'alloc_size'};

  if ( $self->_stor($file_rem) ) {

    my ( $data, $written, $io );

    $io = $self->_get_data_channel ();

    print STDERR "put() trace ."  if (${*$self}{'trace'});
    my $cnt = 0;

    while ( ( my $len = sysread $localfd, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on put(): $!\n";
      }

      if ($fix_cr_issue) {
         $data =~ s/\n/\015\012/g;
         $len = length ($data);
      }

      print STDERR "."  if (${*$self}{'trace'} && ($cnt % TRACE_MOD) == 0);
      ++$cnt;

      $written = syswrite $io, $data, $len;
      croak "System write error on put(): $!\n" unless defined $written;
    }
    print STDERR ". done!\n"  if (${*$self}{'trace'});

    close ($localfd)  if ($close_file);
    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;
  }

  close ($localfd)  if ($close_file);

  return undef;
}

sub uput {              # Unique put (STOU command)
  my $self     = shift;
  my $file_loc = shift;
  my $file_rem = shift;
  my ( $size, $localfd );
  my $close_file = 0;

  $size = ${*$self}{'buf_size'} || 2048;

  unless ( $self->pasv() ) {
    $self->_abort();
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;
    croak "If you had passed a stream, you must specify the remote filename."
      unless $file_rem;
  }
  else {
    unless ( open( $localfd, "< $file_loc" ) ) {
      $self->_abort();
      croak "Can't open local file!";
    }
    $close_file = 1;
  }

  unless ($file_rem) {
     require File::Basename;
     $file_rem = File::Basename::basename ($file_loc);
  }

  my $fix_cr_issue = 1;
  if ( ${*$self}{'type'} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
    $fix_cr_issue = 0;
  }

  # If alloc_size is already set, I skip this part
  unless ( defined ${*$self}{'alloc_size'} ) {
    if ( -f $file_loc ) {
      my $size = -s $file_loc;
      $self->alloc($size);
    }
  }

  delete ${*$self}{'alloc_size'};

  if ( $self->_stou($file_rem) ) {

    my ( $data, $written, $io );

    $io = $self->_get_data_channel ();

    print STDERR "uput() trace ."  if (${*$self}{'trace'});
    my $cnt = 0;

    while ( ( my $len = sysread $localfd, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on uput(): $!\n";
      }

      if ($fix_cr_issue) {
         $data =~ s/\n/\015\012/g;
         $len = length ($data);
      }

      print STDERR "."  if (${*$self}{'trace'} && ($cnt % TRACE_MOD) == 0);
      ++$cnt;

      $written = syswrite $io, $data, $len;
      croak "System write error on uput(): $!\n" unless defined $written;
    }
    print STDERR ". done!\n"  if (${*$self}{'trace'});

    close ($localfd)  if ($close_file);
    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;
  }

  close ($localfd)  if ($close_file);

  return undef;
}

sub alloc {
  my $self = shift;
  my $size = shift;

  if ( $self->_alloc($size) ) {
    ${*$self}{'alloc_size'} = $size;
  }
  else {
    return 0;
  }

  return 1;
}

sub delete {
  my $self = shift;
  $self->command( "DELE", @_ );
  return ( $self->response == CMD_OK );
}

sub auth {
  my $self = shift;
  $self->command( "AUTH", "TLS" );
  return ( $self->response == CMD_OK );
}

sub pwd {
  my $self = shift;
  my $path;

  $self->command("PWD");
  $self->response();

  if ( ${*$self}{'last_ftp_msg'} =~ /\"(.*)\".*/ )
  {    # 257 "/<PATH>/" is current directory.
    ( $path = $1 ) =~
      s/\"\"/\"/g;    # "Quote-doubling" convention - RFC 959, Appendix II
    return $path;
  }
  else {
    return undef;
  }
}

sub cwd {
  my $self = shift;
  $self->command( "CWD", @_ );
  return ( $self->response == CMD_OK );
}

sub noop {
  my $self = shift;
  $self->command("NOOP");
  return ( $self->response == CMD_OK );
}

sub rename {
  my $self     = shift;
  my $old_name = shift;
  my $new_name = shift;

  return 0 unless $self->_rnfr($old_name);
  return 0 unless $self->_rnto($new_name);
  return 1;

}

sub cdup {
  my $self = shift;
  $self->command("CDUP");
  return ( $self->response == CMD_OK );
}

# TODO: Make mkdir() working with recursion.
sub mkdir {
    my $self = shift;
    my $dir = shift;
    $self->command("MKD", $dir);
    return ( $self->response == CMD_OK );
}

# TODO: Make rmdir() working with recursion.
sub rmdir {
    my $self = shift;
    my $dir = shift;
    $self->command("RMD", $dir);
    return ( $self->response == CMD_OK );
}

sub site {
  my $self = shift;

  $self->command("SITE", @_);
  return ( $self->response == CMD_OK );
}

sub supported {
   my $self = shift;
   my $cmd = uc (shift);
   my $site_cmd = shift;

   my $result = 0;        # Assume invalid FTP command

   # It will cache the result so OK to call multiple times.
   my $help = $self->_help ();

   # Only finds exact matches, no abbreviations like some FTP servers allow.
   if (defined $cmd && exists $help->{$cmd}) {
      $result = 1;           # Was a valid FTP command
      ${*$self}{'last_ftp_msg'} = "214 The $cmd command is supported.";
   } else {
      ${*$self}{'last_ftp_msg'} = "502 Unknown command $cmd.";
   }

   # Are we validating a SITE sub-command?
   if ($result && $cmd eq "SITE" && defined $site_cmd) {
      my $help2 = $self->_help ($cmd);
      if (exists $help2->{uc ($site_cmd)}) {
         ${*$self}{'last_ftp_msg'} = "214 The $cmd sub-command $site_cmd is supported.";
      } else {
         ${*$self}{'last_ftp_msg'} = "502 Unknown $cmd sub-command - $site_cmd.";
         $result = 0;     # It failed after all!
      }
   }

   print STDERR "<<+ " . ${*$self}{'last_ftp_msg'} . "\n" if ${*$self}{'debug'};

   return ($result);
}

# Allow the user to send a command directly, BE CAREFUL !!

sub quot {
   my $self = shift;
   my $cmd  = uc (shift);

   unless ($self->supported ($cmd)) {
      return (CMD_REJECT);
   }

   # The following FTP commands are known to open a data channel
   if ($cmd eq "STOR" || $cmd eq "RETR" ||
       $cmd eq "NLST" || $cmd eq "LIST" ||
       $cmd eq "STOU" || $cmd eq "APPE") {
      ${*$self}{'last_ftp_msg'} = "522 Data Connections not supported via quot().";
      return (CMD_REJECT);
   }

   $self->command ($cmd, @_);
   return ($self->response ());
}

#-----------------------------------------------------------------------
#  Type setting function
#-----------------------------------------------------------------------

sub ascii {
  my $self = shift;
  ${*$self}{'type'} = MODE_ASCII;
  return $self->_type(MODE_ASCII);
}

sub binary {
  my $self = shift;
  ${*$self}{'type'} = MODE_BINARY;
  return $self->_type(MODE_BINARY);
}

#-----------------------------------------------------------------------
#  Internal functions
#-----------------------------------------------------------------------

sub _user {
  my $self = shift;
  $self->command( "USER", @_ );
  return $self->response;
}

sub _passwd {
  my $self = shift;
  $self->command( "PASS", @_ );
  return $self->response;
}

sub _quit {
  my $self = shift;
  $self->command("QUIT");
  return ( $self->response == CMD_OK );
}

sub _prot {
  my $self = shift;
  my $opt = shift || ${*$self}{'data_prot'};
  $self->command( "PROT", $opt );     # C, S, E or P.
  my $res = ( $self->response == CMD_OK );

  # Check if someone changed the data channel protection mode ...
  if ($res && $opt ne ${*$self}{'data_prot'}) {
    ${*$self}{'data_prot'} = $opt;   # They did!
  }

  return ( $res );
}

# Depreciated, only present to make backwards compatable with v0.05 & earlier.
sub _protp {
  my $self = shift;
  return ($self->_prot (DATA_PROT_PRIVATE));
}

sub _pbsz {
  my $self = shift;
  $self->command( "PBSZ", "0" );
  return ( $self->response == CMD_OK );
}

sub _nlst {
  my $self = shift;
  $self->command( "NLST", @_ );
  return ( $self->response == CMD_INFO );
}

sub _list {
  my $self = shift;
  $self->command( "LIST", @_ );
  return ( $self->response == CMD_INFO );
}

sub _type {
  my $self = shift;
  $self->command( "TYPE", @_ );
  return ( $self->response == CMD_OK );
}

sub _retr {
  my $self = shift;
  $self->command( "RETR", @_ );
  return ( $self->response == CMD_INFO );
}

sub _stor {
  my $self = shift;
  $self->command( "STOR", @_ );
  return ( $self->response == CMD_INFO );
}

sub _stou {
  my $self = shift;
  $self->command( "STOU", @_ );
  return ( $self->response == CMD_INFO );
}

sub _abort {
  my $self = shift;
  $self->command("ABOR");
  return ( $self->response == CMD_OK );
}

sub _alloc {
  my $self = shift;
  $self->command( "ALLO", @_ );
  return ( $self->response == CMD_OK );
}

sub _rnfr {
  my $self = shift;
  $self->command( "RNFR", @_ );
  return ( $self->response == CMD_MORE );
}

sub _rnto {
  my $self = shift;
  $self->command( "RNTO", @_ );
  return ( $self->response == CMD_OK );
}

#-----------------------------------------------------------------------
#  Checks what commands are available on the remote server
#-----------------------------------------------------------------------

sub _help {
   # Only shift off self, bug otherwise!
   my $self = shift;
   my $cmd = uc ($_[0]);   # Will convert undef to "". (Do not do a shift!)

   # Check if requesting a list of all commands or details on specific command.
   my $all_cmds = (! defined $_[0]);
   my $site_cmd = ($cmd eq "SITE");

   my %help;

   # Now see if we've cached the result previously ...
   if ($all_cmds && exists ${*$self}{'help_cmds_msg'}) {
      ${*$self}{'last_ftp_msg'} = ${*$self}{'help_cmds_msg'};
      return ( ${*$self}{'help_cmds_found'} );

   } elsif (exists ${*$self}{"help_${cmd}_msg"}) {
      ${*$self}{'last_ftp_msg'} = ${*$self}{"help_${cmd}_msg"};
      my $hlp = ${*$self}{"help_${cmd}_found"};
      return ( (defined $hlp) ? $hlp : \%help );
   }

   $self->command ("HELP", @_);

   # Now lets see if we need to parse the result to get a hash of the
   # supported FTP commands on the other server ...
   if ($self->response () == CMD_OK && ($all_cmds || $site_cmd)) {
      my $helpmsg = $self->last_message ();
      my @lines = split (/\n/, $helpmsg);

      foreach my $line (@lines) {
         # Strip off the code & separator or leading blanks if multi line.
         $line =~ s/(^[0-9]+[\s-])|(^\s+)//;

         my $lead = (defined $2);   # Flag tells if partial multi line response.

         my @lst = split (/[\s,.]+/, $line);  # Break into individual commands

         if ( $site_cmd && $lst[0] eq "SITE" && $lst[1] =~ m/^[A-Z]+$/ ) {
            $help{$lst[1]} = 1;    # Each line: SITE CMD mixed-case-usage
         }
         # Now only process if nothing is in lower case (ie: its a comment)
         # All commands must be in upper case, some special chars not allowed.
         # Commands ending in "*" are currently turned off.
         elsif ( $line !~ m/[a-z()]/ ) {
            foreach (@lst) {
               $help{$_} = 1   if ($_ !~ m/[*]$/);
            }
         }
      }

      # If we don't find anything, it's a problem.  So don't cache if so ...
      if (scalar (keys %help) > 0) {
         if ($all_cmds) {
            # Add the assumed OPTS command required if FEAT is supported!
            # Even though not all servers support OPTS as required with FEAT.
            $help{"OPTS"} = 1  if ($help{"FEAT"});     # RFC 2389
            ${*$self}{'help_cmds_found'} = \%help;
            ${*$self}{'help_cmds_msg'} = $helpmsg;
         } else {
            ${*$self}{"help_${cmd}_found"} = \%help;
            ${*$self}{"help_${cmd}_msg"} = $helpmsg;
         }
      }
   } else {
      ${*$self}{"help_${cmd}_msg"} = $self->last_message ();
   }

   return (\%help);
}

#-----------------------------------------------------------------------
#  Messages handler
#-----------------------------------------------------------------------

sub command {
  my $self = shift;
  my @args;
  my $data;

  # remove undef values from the list.
  # Maybe I have to find out why those undef were passed.
  @args = grep defined($_), @_ ;

  $data = join(
    " ",
    map {
      /\n/
        ? do { my $n = $_; $n =~ tr/\n/ /; $n }
        : $_;
      } @args
  );

  if ( ${*$self}{'debug'} ) {
     my $prefix = ( ref($self) eq "Net::FTPSSL" ) ? ">>> " : "SKT >>> ";
     if ( $data =~ m/^PASS\s/ ) {
        print STDERR $prefix . "PASS *******\n";   # Don't echo passwords
     } else {
        print STDERR $prefix . $data . "\n";       # Echo everything else
     }
  }

  $data .= "\015\012";

  my $written;
  my $len = length $data;
  $written = syswrite( $self, $data, $len );
  unless ( defined $written ) {
    carp "Can't write on socket: $!";
    $self->close;
    return undef;
  }

  return 1;
}

# Some responses take multiple lines to finish.  So be careful, you will
# be blocked if you read past the last row of the response!
sub response {
  my $self = shift;
  my ( $data, $code, $sep, $desc ) = ( "", CMD_ERROR, "-", "" );

  ${*$self}{'last_ftp_msg'} = "";   # Clear out the old message
  my $prefix = ( ref($self) eq "Net::FTPSSL" ) ? "<<< " : "SKT <<< ";

  while ($sep eq "-") {
     my $read = sysread( $self, $data, 4096);
     unless( defined $read ) {
         croak "Can't read on socket: $!";
     }

     # The above sysread() should only read in a single response msg.
     # But multiple response messages per sysread() is no problem.
     # But some responses have embedded CR, so no codes appear on those lines!
     my @lines = split( "\015\012", $data );

     foreach my $line ( @lines ) {

       print STDERR $prefix . $line . "\n"   if ${*$self}{'debug'};

#      $data = $self->getline();
#      $data =~ m/^(\d+)(\-?)(.*)$/s;
       $line =~ m/^(\d+)([-\s]?)(.*)$/s;

       ($code, $sep, $desc) = ($1, $2, $3);

       ${*$self}{'last_ftp_msg'} .= $line;

       last if (defined $sep && $sep ne '-');

       ${*$self}{'last_ftp_msg'} .= "\n";
     }

     # Only true if the last response message had CR's embeded in it!
     $sep = "-" unless (defined $sep);
  }

  return substr( $code, 0, 1 );
}

sub last_message {
   my $self = shift;
   return ${*$self}{'last_ftp_msg'};
}

#-----------------------------------------------------------------------
#  Added to make backwards compatable with Net::FTP
#-----------------------------------------------------------------------
sub message {
   my $self = shift;
   return ${*$self}{'last_ftp_msg'};
}

1;

__END__

=head1 NAME

Net::FTPSSL - A FTP over SSL/TLS class

=head1 VERSION 0.06

=head1 SYNOPSIS

  use Net::FTPSSL;

  my $ftps = Net::FTPSSL->new('ftp.yoursecureserver.com', 
                              Port => 21,
                              Encryption => 'E',
                              Debug => 1) 
    or die "Can't open ftp.yoursecureserver.com";

  $ftps->login('anonymous', 'user@localhost') 
    or die "Can't login: ", $ftps->last_message();

  $ftps->cwd("/pub") or die "Can't change directory: " . $ftps->last_message;

  $ftps->get("file") or die "Can't get file: " . $ftps->last_message;

  $ftps->quit();

=head1 DESCRIPTION

C<Net::FTPSSL> is a class implementing a simple FTP client over a Secure
Shell Layer (SSL) connection written in Perl as described in RFC959 and
RFC2228.

=head1 CONSTRUCTOR

=over 4

=item new ( HOST [, OPTIONS ])

Creates a new B<Net::FTPSSL> object and opens a connection with the
C<HOST>. C<HOST> is the address of the FTP server and it's a required
argument. OPTIONS are passed in a hash like fashion, using key and value
pairs.

C<OPTIONS> are:

B<Port> - The port number to connect to on the remote FTP server.
Default value is 21 for B<EXP_CRYPT> or 990 for B<IMP_CRYPT>.

B<Encryption> - The connection can be implicitly (B<IMP_CRYPT>) or
explicitly (B<EXP_CRYPT>) encrypted.
In explicit cases the connection begins clear and became encrypted after an
"AUTH" command is sent. Default value is B<EXP_CRYPT>.

B<DataProtLevel> - The level of security on the data channel.  Default is B<P>,
where everything is encrypted. B<C> is clear, and mixed are B<S> and B<E>.

B<useSSL> - Use this option to connect to the server using SSL instead of TLS.
TLS is the default encryption type and the more secure of the two protocalls.
Set B<useSSL => 1> to use SSL.

B<Timeout> - Set a connection timeout value. Default value is 120.

B<Buffer> - This is the block size that Net::FTPSSL will use when a transfer is
made. Default value is 10240.

B<Debug> - This set the debug informations option on/off. Default is off.

B<Trace> - Turns on/off put/get download tracing to STDERR.  Default is off.

=back

=head1 METHODS

Most of the methods return I<true> or I<false>, true when the operation was
a succes and false when failed. Methods like B<list> or B<nlst> return an
empty array when fail.

=over 4

=item login(USER, PASSWORD)

Use the given informations to log into the FTP server.

=item list([DIRECTORY])

This method returns a list of files in this format:

 total 5
 drwxrwx--- 1 owner group          512 May 31 11:16 .
 drwxrwx--- 1 owner group          512 May 31 11:16 ..
 drwxrwx--- 1 owner group          512 Oct 27  2004 foo
 drwxrwx--- 1 owner group          512 Oct 27  2004 pub
 drwxrwx--- 1 owner group          512 Mar 29 12:09 bar

If DIRECTORY is omitted, the method will return the list of the current
directory.

=item nlst([DIRECTORY])

Same as C<list> but returns the list in this format:

 foo
 pub
 bar

Personally, I suggest to use list instead of nlst.

=item ascii

Sets the transfer file in ASCII mode.

=item binary

Sets the transfer file in binary mode. No transformation will be done.

=item get(REMOTE_FILE, [LOCAL_FILE])

Retrives the REMOTE_FILE from the ftp server. LOCAL_FILE may be a filename or a
filehandle.  Return undef if it fails.

=item put(LOCAL_FILE, [REMOTE_FILE])

Stores the LOCAL_FILE into the remote ftp server. LOCAL_FILE may be filehandle,
but in this case REMOTE_FILE is required. Return undef if it fails.

=item uput(LOCAL_FILE, [REMOTE_FILE])

Stores the LOCAL_FILE into the remote ftp server. LOCAL_FILE may be filehandle,
but in this case REMOTE_FILE is required.  If REMOTE_FILE already exists, a
unique name is calculated from it.  Return undef if it fails.

=item delete(REMOTE_FILE)

Deletes the indicated REMOTE_FILE.

=item cwd(DIR)

Attempts to change directory to the directory given in DIR.

=item pwd

Returns the full pathname of the current directory.

=item cdup

Changs directory to the parent of the current directory.

=item mkdir(DIR)

Creates the indicated directory. No recursion at the moment.

=item rmdir(DIR)

Removes the empty indicated directory. No recursion at the moment.

=item noop

It specifies no action other than the server send an OK reply.

=item site(ARGS)

Send a SITE command to the remote server and wait for a response.

=item supported(CMD [,SITE_OPT])

Returns TRUE if the remote server supports the given command.  CMD must match
exactly.  If the CMD is SITE and SITE_OPT is supplied, it will also check if
the specified SITE_OPT sub-command is supported.

=item quot(CMD [,ARGS])

Send a command, that Net::FTPSSL does not directly support, to the remote
server and wait for a response.

Returns the most significant digit of the response code.

B<WARNING> This call should only be used on commands that do not require
data connections.  Misuse of this method can hang the connection if the
internal list of FTP commands using a data channel is incomplete.

=item last_message() or message()

Use either one to collect the last response from the FTP server.  This is the
same response printed to STDERR when trace is turned on.

=back

=head1 AUTHOR

Marco Dalla Stella - <kral at paranoici dot org>

=head1 MAINTAINER

Curtis Leach - As of v0.05

=head1 SEE ALSO

L<Net::Cmd>

L<Net::FTP>

L<Net::SSLeay::Handle>

L<IO::Socket::SSL>

RFC 959 - L<ftp://ftp.rfc-editor.org/in-notes/rfc959.txt>

RFC 2228 - L<ftp://ftp.rfc-editor.org/in-notes/rfc2228.txt>

RFC 4217 - L<ftp://ftp.rfc-editor.org/in-notes/rfc4217.txt>

=head1 CREDITS

Graham Barr <gbarr at pobox dot com> - for have written such a great
collection of modules (libnet).

=head1 BUGS

I'm currently testing the module with proftpd and Titan FTP. I'm having a lot
of trouble with the second at the moment. Put or get phases seem to work ok
(sysread and syswrite don't return any errors) but the server doesn't receive
all the sent data. I'm working on it.

=head1 COPYRIGHT

Copyright (c) 2005 Marco Dalla Stella. All rights reserved.  This
program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

