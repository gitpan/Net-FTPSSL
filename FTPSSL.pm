# File    : Net::FTPSSL
# Author  : kral <kral at paranici dot org>
# Created : 01 March 2005
# Version : 0.08
# Revision: $Id: FTPSSL.pm,v 1.24 2005/10/23 14:37:12 kral Exp $

package Net::FTPSSL;

use strict;
use warnings;
use vars qw( $VERSION @EXPORT $ERRSTR );
use base ( 'Exporter', 'IO::Socket::SSL' );
use IO::Socket::INET;
use Net::SSLeay::Handle;
use File::Basename;
use Time::Local;
use Sys::Hostname;
use Carp qw( carp croak );
use Errno qw/ EINTR /;

$VERSION = "0.08";
@EXPORT  = qw( IMP_CRYPT  EXP_CRYPT  CLR_CRYPT
               DATA_PROT_CLEAR  DATA_PROT_PRIVATE
               DATA_PROT_SAFE   DATA_PROT_CONFIDENTIAL
               CMD_INFO  CMD_OK      CMD_MORE    CMD_REJECT
               CMD_ERROR CMD_PROTECT CMD_PENDING );
$ERRSTR = "No Errors Detected Yet.";

# Command Channel Protection Levels
use constant IMP_CRYPT => "I";
use constant EXP_CRYPT => "E";       # Default
use constant CLR_CRYPT => "C";

# Data Channel Protection Levels
use constant DATA_PROT_CLEAR        => "C";   # Least secure!
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

# File transfer modes
use constant MODE_BINARY => "I";
use constant MODE_ASCII  => "A";

use constant TRACE_MOD => 5;   # How many iterations between ".".  Must be >= 2.

sub new {
  my $self         = shift;
  my $type         = ref($self) || $self;
  my $host         = shift;
  my $arg          = (ref ($_[0]) eq "HASH") ? $_[0] : {@_};

  my %ssl_args;    # Only referenced via $advanced.

  my $encrypt_mode = $arg->{Encryption} || EXP_CRYPT;
  my $port         = ($encrypt_mode eq IMP_CRYPT)
                               ? 990 : ($arg->{Port} || 21);
  my $debug        = $arg->{Debug} || 0;
  my $timeout      = $arg->{Timeout} || 120;
  my $buf_size     = $arg->{Buffer} || 10240;
  my $trace        = $arg->{Trace} || 0;
  my $data_prot    = ($encrypt_mode eq CLR_CRYPT) ? DATA_PROT_CLEAR
                                 : ($arg->{DataProtLevel} || DATA_PROT_PRIVATE);
  my $use_ssl      = $arg->{useSSL} || 0;
  my $die          = $arg->{Croak} || $arg->{Die};
  my $pres_ts      = $arg->{PreserveTimestamp} || 0;

  # Using this feature is unsupported.  Use at own risk!
  my $advanced     = (ref ($arg->{SSL_Advanced}) eq "HASH")
                                   ? $arg->{SSL_Advanced} : \%ssl_args;

  return _croak_or_return (undef, $die, $debug, "Host undefined")  unless $host;

  return _croak_or_return (undef, $die, $debug,
                           "Encryption mode unknown!  ($encrypt_mode)")
      if ( $encrypt_mode ne IMP_CRYPT && $encrypt_mode ne EXP_CRYPT &&
           $encrypt_mode ne CLR_CRYPT );

  return _croak_or_return (undef, $die, $debug,
                           "Data Channel mode unknown! ($data_prot)")
      if ( $data_prot ne DATA_PROT_CLEAR &&
           $data_prot ne DATA_PROT_SAFE &&
           $data_prot ne DATA_PROT_CONFIDENTIAL &&
           $data_prot ne DATA_PROT_PRIVATE );

  # We start with a clear connection, 'cause I don't know if the
  # connection will be implicit or explicit or clear after all'.
  my $socket = IO::Socket::INET->new (
                         PeerAddr => $host,
                         PeerPort => $port,
                         Proto    => 'tcp',
                         Timeout  => $timeout
                         )
                   or
            return _croak_or_return (undef, $die, $debug,
                                  "Can't open tcp connection! ($host:$port)");

  $socket->autoflush(1);
  ${*$socket}{debug} = $debug;
  ${*$socket}{Croak} = $die;

  my $obj;

  if ( $encrypt_mode eq CLR_CRYPT ) {
     # Catch the banner from the connection request ...
     return _croak_or_return ($socket)  unless ( response($socket) == CMD_OK );

     # Leave the command channel clear for regular FTP.
     $obj = $socket;
     bless ( $obj, $type );
     ${*$obj}{_SSL_opened} = 0;      # To get rid of warning on close ...

  } else {
     # Determine the SSL_version to use ...
     my $mode = $use_ssl ? "SSLv23" : "TLSv1";

     # Determine the options to use in start_SSL() ...
     # ------------------------------------------------------------------------
     # Only SSL_version & Timeout are supported.  All others are unsupported.
     # Doing this merge as a courtesy, so the regular options can be overridden
     # by this advanced functionality.
     # ------------------------------------------------------------------------
     if (defined $advanced->{SSL_version}) {
        $mode = $advanced->{SSL_version};      # Mode was overridden.
        $use_ssl = ( $mode !~ m/^TLSv1$/i );   # Reset in case it conflicts ...
     } else {
        $advanced->{SSL_version} = $mode;      # Nothing overridden.
     }
     $advanced->{Timeout} = $timeout  unless (exists $advanced->{Timeout});
     # ------------------------------------------------------------------------

     if ( $encrypt_mode eq EXP_CRYPT ) {
        # Catch the banner from the connection request ...
        return _croak_or_return ($socket) unless (response ($socket) == CMD_OK);

        # In explicit mode FTPSSL sends an AUTH TLS/SSL command, catch the msgs
        command( $socket, "AUTH", ($use_ssl ? "SSL" : "TLS") );
        return _croak_or_return ($socket) unless (response ($socket) == CMD_OK);
     }

     # Now transform the clear connection into a SSL one on our end.
     $obj = $type->start_SSL( $socket, $advanced )
               or return _croak_or_return ( $socket, undef,
                                      "$mode: " . IO::Socket::SSL::errstr () );

     if ( $encrypt_mode eq IMP_CRYPT ) {
        # Catch the banner from the implicit connection request ...
        return $obj->_croak_or_return ()  unless ( $obj->response() == CMD_OK );
     }
  }

  # Print out the details of the SSL object.  Set to TRUE only for debugging!
  if ( $debug && ref ($arg->{SSL_Advanced}) eq "HASH" ) {
     print STDERR "\nObject SSL Details ... ($host:$port - $encrypt_mode)\n";
     foreach (keys %{*$obj}) {
        my $x = ${*$obj}{$_};
        $x="(undef)" unless (defined $x);
        $x = join ("\n         ", split (/\n/, $x))  if (! ref($x));
        print STDERR "  $_ ==> $x\n";
        if ($x =~ m/HASH\(0/) {
           foreach (keys %{$x}) {
              my $y = $x->{$_};
              $y="(undef)" unless (defined $y);
              $y = join ("\n                   ", split (/\n/, $y)) if (! ref($y));
              print STDERR "        -- $_ ===> $y\n";
           }
        }
     }
     print STDERR "\n";
  }

  # These options control the behaviour of the Net::FTPSSL class ...
  ${*$obj}{Crypt}     = $encrypt_mode;
  ${*$obj}{debug}     = $debug;
  ${*$obj}{timeout}   = $timeout;
  ${*$obj}{buf_size}  = $buf_size;
  ${*$obj}{type}      = MODE_ASCII;
  ${*$obj}{trace}     = $trace;
  ${*$obj}{data_prot} = $data_prot;
  ${*$obj}{Croak}     = $die;
  ${*$obj}{FixPutTs}  = ${*$obj}{FixGetTs} = $pres_ts;

  return $obj;
}

#-----------------------------------------------------------------------
# TODO:  Adding ACCT (Account) support (response 332 [CMD_MORE] on password)

sub login {
  my ( $self, $user, $pass ) = @_;

  my $logged_on = $self->_test_croak ( $self->_user ($user) &&
                                       $self->_passwd ($pass) );

  if ( $logged_on ) {
     if ( ${*$self}{FixPutTs} && ! $self->supported ("MFMT") ) {
        ${*$self}{FixPutTs} = 0;    # Not supported by this server after all!
     }
     if ( ${*$self}{FixGetTs} && ! $self->supported ("MDTM") ) {
        ${*$self}{FixGetTs} = 0;    # Not supported by this server after all!
     }
  }

  return ( $logged_on );
}

#-----------------------------------------------------------------------

sub quit {
  my $self = shift;
  $self->_quit() or return 0;   # Don't do a croak here, since who tests?
  $self->close();
  return 1;
}

sub pasv {
  my $self = shift;

  # Only need to do this for encrypted Command Channels.
  if ( ${*$self}{Crypt} ne CLR_CRYPT ) {
     $self->_pbsz();
     unless ($self->_prot()) { return $self->_croak_or_return (); }
  }

  $self->command("PASV");

  # my $msg = $self->getline();
  # print STDERR "<<< " . $msg if ${*$self}{debug};
  # unless ( substr( $msg, 0, 1 ) == CMD_OK ) { return undef; }

  unless ( $self->response () == CMD_OK ) { return $self->_croak_or_return (); }
  my $msg = $self->last_message ();

  $msg =~ m/(\d+)\s(.*)\(((\d+,?)+)\)\.?/
    ;    # [227] [Entering Passive Mode] ([h1,h2,h3,h4,p1,p2]).

  my @address = split( /,/, $3 );

  my $host = join( '.', @address[ 0 .. 3 ] );
  my $port = $address[4] * 256 + $address[5];

  my $socket;
  if ( ${*$self}{data_prot} eq DATA_PROT_PRIVATE ) {
     $socket = Net::SSLeay::Handle->make_socket( $host, $port )
               or return $self->_croak_or_return (0,
                           "Can't open private data connection to $host:$port");

  } elsif ( ${*$self}{data_prot} eq DATA_PROT_CLEAR ) {
     $socket = IO::Socket::INET->new( PeerAddr => $host, PeerPort => $port,
                                      Proto => 'tcp',
                                      Timeout => ${*$self}{timeout} )
               or return $self->_croak_or_return (0,
                             "Can't open clear data connection to $host:$port");

  } else {
     # TODO: Fix so DATA_PROT_SAFE & DATA_PROT_CONFIDENTIAL work.
     return $self->_croak_or_return (0, "Currently doesn't support mode ${*$self}{data_prot} for data channels to $host:$port");
  }

  ${*$self}{data_ch} = \*$socket;

  return 1;
}

sub _get_data_channel {
   my $self = shift;

   my $io;
   if ( ${*$self}{data_prot} eq DATA_PROT_PRIVATE ) {
      $io = IO::Handle->new ();
      tie ( *$io, "Net::SSLeay::Handle", ${*$self}{data_ch} );

   } elsif ( ${*$self}{data_prot} eq DATA_PROT_CLEAR ) {
      $io = ${*$self}{data_ch};

   } else {
      # TODO: Fix so DATA_PROT_SAFE & DATA_PROT_CONFIDENTIAL work.
      return $self->_croak_or_return (0, "Currently doesn't support mode ${*$self}{data_prot} for data channels.");
   }

   $io->autoflush (1);

   return ( $io );
}

sub nlst {
  my $self = shift;

  return ( $self->list (@_) );
}

sub list {
  my $self = shift;
  my $path = shift || undef;     # Causes "" to be treated as "."!
  my $pattern = shift || undef;  # Only wild cards are * and ? (same as ls cmd)

  my $dati;

  unless ( $self->pasv() ) {
    return undef;    # Already decided not to call croak if you get here!
  }

  # "(caller(1))[3]" returns undef if not called by another Net::FTPSSL method!
  my $c = (caller(1))[3];
  my $nlst_flg = ( defined $c && $c eq "Net::FTPSSL::nlst" );

  if ( $nlst_flg ? $self->_nlst($path) : $self->_list($path) ) {
    my ( $tmp, $io, $size );

    $size = ${*$self}{buf_size};

    $io = $self->_get_data_channel ();
    unless ( defined $io ) {
       return undef;   # Already decided not to call croak if you get here!
    }

    while ( my $len = sysread $io, $tmp, $size ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        my $type = $nlst_flg ? 'nlst()' : 'list()';
        return $self->_croak_or_return (0, "System read error on read while $type: $!");
      }
      $dati .= $tmp;
    }

    $io->close();

    $self->response ();    # For catch "226 Closing data connection."
  }

  # Convert to use local separators ...
  # Required for callback functionality ...
  $dati =~ s/\015\012/\n/g;

  # Remove that pesky total that isn't returned from all FTPS servers.
  # This way we are consistant for everyone!
  # Another reason to strip it out is that it's the total block size,
  # not the total number of files.  Which gets confusing.
  # Works no matter where the total is in the string ...
  unless ( $nlst_flg) {
     $dati =~ s/^\n//s   if ( $dati =~ s/^\s*total\s+\d+\s*$//mi );
     $dati =~ s/\n\n/\n/s;    # In case total not 1st line ...
  }

  # What if we asked to use patterns to limit the listing returned ?
  if ( defined $pattern ) {
     my $p = $pattern;   # So can display original pattern later on.

     # Convert from shell wild cards into a perl regular expression ...
     $pattern =~ s/[.]/\\./g;
     $pattern =~ s/[?]/./g;

     if ( $nlst_flg ) {
        if ( $pattern =~ m/[*]/ ) {
           # Don't allow path separators in the string ...
           # Can't do this with regular expressions ...
           $pattern = join ( "[^\\\\/]*", split (/\*/, $pattern . "XXX") );
           $pattern =~ s/XXX$//;
        }
        $pattern = '(^|[\\\\/])' . $pattern . '$';

     } else {
        $pattern =~ s/[*]/\\S*/g;    # No spaces in file's name is allowed!
        $pattern = '\s+(' . $pattern . ')($|\s+->\s+)';
     }

     print STDERR "PATTERN: <- $p => $pattern ->\n"  if ( ${*$self}{debug} );

     # Now only keep those files that match the pattern.
     my @res;
     foreach ( split ( /\n/, $dati ) ) {
        push (@res, $_)  if ( $_ =~ m/$pattern/i );
     }
     $dati = join ("\n", @res);
  }

  my $len = length ($dati);
  my $lvl = $nlst_flg ? 2 : 1;
  my $total = 0;

  if ( $len > 0 ) {
     $total = $self->_call_callback ($lvl, \$dati, \$len, 0);
  }

  # Process trailing call back info if present.
  my $trail;
  ($trail, $len, $total) = $self->_end_callback ($lvl, $total);
  if ( $trail ) {
     $dati .= $trail;
  }

  return $dati ? split( /\n/, $dati ) : ();
}

sub get {
  my $self     = shift;
  my $file_rem = shift;
  my $file_loc = shift;

  my ( $size, $localfd );
  my $close_file = 0;

  unless ($file_loc) {
    $file_loc = basename($file_rem);
  }

  $size = ${*$self}{buf_size} || 2048;

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;

  } else {
    unless ( open( $localfd, "> $file_loc" ) ) {
      return $self->_croak_or_return(0, "Can't create local file! ($file_loc)");
    }
    $close_file = 1;
  }

  my $fix_cr_issue = 1;
  if ( ${*$self}{type} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      return $self->_croak_or_return(0, "Can't set binary mode to local file!");
    }
    $fix_cr_issue = 0;
  }

  unless ( $self->pasv() ) {
    if ( $close_file ) {
       close ($localfd);
       unlink ($file_loc);
    }
    return undef;    # Already decided not to call croak if you get here!
  }

  if ( $self->_retr($file_rem) ) {
    my ( $data, $written, $io );

    $io = $self->_get_data_channel ();
    unless ( defined $io ) {
       if ( $close_file ) {
          close ($localfd);
          unlink ($file_loc);
       }
       return undef;   # Already decided not to call croak if you get here!
    }

    print STDERR "get() trace ."  if (${*$self}{trace});
    my $cnt = 0;
    my $prev = "";
    my $total = 0;
    my $len;

    while ( ( $len = sysread $io, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        return $self->_croak_or_return (0, "System read error on get(): $!");
      }

      if ( $fix_cr_issue ) {
         # What if the line only contained \015 ?  (^M)
         if ( $data eq "\015" ) {
            $prev .= "\015";
            next;
         }

         # What if this line was truncated? (Ends with \015 instead of \015\012)
         # Can't test with reg expr since m/(\015)$/s & m/(\015\012)$/s same!
         # Don't care if it was truncated anywhere else!
         my $last_char = substr ($data, -1);
         if ( $last_char eq "\015" ) {
            $data =~ s/^(.+).$/$prev$1/s;
            $prev = $last_char;
         }

         # What if the previous line was truncated?  But not this one.
         elsif ( $prev ne "" ) {
            $data = $prev . $data;
            $prev = "";
         }

         $data =~ s/\015\012/\n/g;
         $len = length ($data);
      }

      print STDERR "."  if (${*$self}{trace} && ($cnt % TRACE_MOD) == 0);
      ++$cnt;

      $total = $self->_call_callback (1, \$data, \$len, $total);

      if ( $len > 0 ) {
         $written = syswrite $localfd, $data, $len;
         return $self->_croak_or_return (0, "System write error on get(): $!")
               unless (defined $written);
      }
    }

    # Potentially write a last ASCII char to the file ...
    if ($prev ne "") {
      $len = length ($prev);
      $total = $self->_call_callback (1, \$prev, \$len, $total);
      if ( $len > 0 ) {
         $written = syswrite $localfd, $prev, $len;
         return $self->_croak_or_return (0, "System write error on get(prev): $!")
               unless (defined $written);
      }
    }

    # Process trailing "callback" info if returned.
    my $trail;
    ($trail, $len, $total) = $self->_end_callback (1, $total);
    if ( $trail ) {
      $written = syswrite $localfd, $trail, $len;
      return $self->_croak_or_return (0, "System write error on get(trail): $!")
            unless (defined $written);
    }

    print STDERR ". done! (" . $self->_fmt_num ($total) . " byte(s))\n"  if (${*$self}{trace});

    $io->close();
    $self->response();    # For catch "226 Closing data connection."

    if ( $close_file ) {
       close ($localfd);
       if ( ${*$self}{FixGetTs} ) {
          my $tm = $self->_mdtm ( $file_rem );
          utime ( $tm, $tm, $file_loc )  if ( $tm );
       }
    }

    return 1;
  }

  close ($localfd)  if ($close_file);

  return $self->_croak_or_return ();
}


sub put {               # Regular put (STOR command)
  my $self = shift;
  my ($resp, $msg1, $msg2, $requested_file_name, $tm) = $self->_common_put (@_);

  if ( $resp && ${*$self}{FixPutTs} && defined $tm ) {
     $self->_mfmt ($tm, $requested_file_name);
  }

  return ( $resp );
}

sub uput {              # Unique put (STOU command)
  my $self = shift;
  my ($resp, $msg1, $msg2, $requested_file_name, $tm) = $self->_common_put (@_);

  # Now lets get the real name of the file generated!
  if ( $resp ) {
    # The file name may appear in either message returned.
    # So lets check both messages merged together!
    my $msg = $msg1 . "\n" . $msg2;

    if ( $msg =~ m/(FILE|name):\s*([^\s)]+)($|[\s)])/im ) {
       $requested_file_name = $2;   # We found an actual name to use ...
    }

    # TODO: Figure out other uput variants to check for besides the ones above.

    # Until then, if we can't find the file name used in the messages,
    # we'll just have to assume that the default file name was used!

    # Now lets update the timestamp for that file on the server ...
    if ( ${*$self}{FixPutTs} && defined $tm ) {
       $self->_mfmt ($tm, $requested_file_name);
    }

    return ( $requested_file_name );
  }

  return ( undef );
}

sub xput {              # A variant of the regular put (STOR command)
   my $self = shift;
   my $file_loc = shift;
   my $file_rem = shift;

   # Only body is required & must be unique on the FTPS server!
   my $prefix  = shift;
   my $postfix = shift;
   my $body    = shift || (hostname () . ".$$");  # Client name + PID

   # So we don't override "", which is OK for these 2 parts.
   $prefix  = "_tmp."  unless ( defined $prefix );
   $postfix = ".tmp"   unless ( defined $postfix );

   my $scratch_name = $prefix . $body . $postfix;

   unless ($file_rem) {
     if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
       return $self->_croak_or_return (0, "When you pass a stream, you must specify the remote filename.");
     }

     $file_rem = basename ($file_loc);
   }

   if ( $scratch_name eq $file_rem ) {
      return $self->_croak_or_return (0, "The scratch name and final name are the same!  ($file_rem)  xput requires that they must be different!" );
   }

   my $help = $self->_help ();
   unless ( $help->{STOR} && $help->{DELE} && $help->{RNFR} && $help->{RNTO} ) {
      return $self->_croak_or_return (0, "Function xput is not supported by this server.");
   }

   # Now lets send the file.  Make sure we can't die during this process ...
   my $die = ${*self}{Croak};
   ${*self}{Croak} = 0;

   my ($resp, $msg1, $msg2, $requested_file_name, $tm) =
                              $self->_common_put ($file_loc, $scratch_name);

   if ( $resp ) {
     # Now lets make it visible to the file recognizer ...
     $resp = $self->rename ( $requested_file_name, $file_rem );

     # Now lets update the timestamp for the file on the server ...
     # It's not an error if the file recognizer grabs it before the
     # timestamp is reset ...
     if ( $resp && ${*$self}{FixPutTs} && defined $tm ) {
        $self->_mfmt ($tm, $file_rem);
     }
   }

   # Delete the scratch file on error, but don't return this as the error msg.
   # We want the actual error encounterd from the put or rename commands!
   unless ($resp) {
     $msg1 = ${*$self}{last_ftp_msg};
     $self->delete ( $scratch_name );
     ${*$self}{last_ftp_msg} = $msg1;
   }

   # Now allow us to die again if we must ...
   ${*self}{Croak} = $die;

   return ( $self->_test_croak ( $resp ) );
}

sub _common_put {
  my $self     = shift;
  my $file_loc = shift;
  my $file_rem = shift;

  my ( $size, $localfd );
  my $close_file = 0;

  # Find out which of 3 "put" functions called me ...
  (caller(1))[3] =~ m/:([^:]+)$/;
  my $func = $1;

  $size = ${*$self}{buf_size} || 2048;

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;
    return $self->_croak_or_return (0, "When you pass a stream, you must specify the remote filename.")
         unless $file_rem;

  } else {
    unless ( open( $localfd, "< $file_loc" ) ) {
      return $self->_croak_or_return (0, "Can't open local file! ($file_loc)");
    }
    $close_file = 1;
  }

  unless ($file_rem) {
    $file_rem = basename($file_loc);
  }

  my $fix_cr_issue = 1;
  if ( ${*$self}{type} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      return $self->_croak_or_return(0, "Can't set binary mode to local file!");
    }
    $fix_cr_issue = 0;
  }

  unless ( $self->pasv() ) {
    close ($localfd)  if ($close_file);
    return undef;    # Already decided not to call croak if you get here!
  }

  # If alloc_size is already set, I skip this part
  unless ( defined ${*$self}{alloc_size} ) {
    if ( -f $file_loc ) {
      my $size = -s $file_loc;
      $self->alloc($size);
    }
  }

  delete ${*$self}{alloc_size};

  if ( $func eq "uput" ? $self->_stou($file_rem) : $self->_stor($file_rem) ) {

    my $put_msg = $self->last_message ();

    my ( $data, $written, $io );

    $io = $self->_get_data_channel ();
    unless ( defined $io ) {
       close ($localfd)  if ($close_file);
       return undef;   # Already decided not to call croak if you get here!
    }

    print STDERR "$func() trace ."  if (${*$self}{trace});
    my $cnt = 0;
    my $total = 0;
    my $len;

    while ( ( $len = sysread $localfd, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        return $self->_croak_or_return (0, "System read error on $func(): $!");
      }

      $total = $self->_call_callback (2, \$data, \$len, $total);

      if ($fix_cr_issue) {
         $data =~ s/\n/\015\012/g;
         $len = length ($data);
      }

      print STDERR "."  if (${*$self}{trace} && ($cnt % TRACE_MOD) == 0);
      ++$cnt;

      if ( $len > 0 ) {
         $written = syswrite $io, $data, $len;
         return $self->_croak_or_return (0, "System write error on $func(): $!")
             unless (defined $written);
      }
    }

    # Process trailing call back info if present.
    my $trail;
    ($trail, $len, $total) = $self->_end_callback (2, $total);
    if ( $trail ) {
      if ($fix_cr_issue) {
         $trail =~ s/\n/\015\012/g;
         $len = length ($trail);
      }
      $written = syswrite $io, $trail, $len;
      return $self->_croak_or_return (0, "System write error on $func(): $!")
          unless (defined $written);
    }

    print STDERR ". done! (" . $self->_fmt_num ($total) . " byte(s))\n"  if (${*$self}{trace});

    my $tm;
    if ($close_file) {
       close ($localfd);
       if ( ${*$self}{FixPutTs} ) {
          $tm = (stat ($file_loc))[9];   # The local file's timestamp!
       }
    }

    $io->close();
    $self->response();    # For catch "226 Closing data connection."

    return ( 1, $put_msg, $self->last_message (), $file_rem, $tm );
  }

  close ($localfd)  if ($close_file);

  return ( $self->_croak_or_return (), undef, undef, $file_rem, undef );
}

# On some servers this command always fails!
# So no croak test!
sub alloc {
  my $self = shift;
  my $size = shift;

  if ( $self->_alloc($size) ) {
    ${*$self}{alloc_size} = $size;
  }
  else {
    return 0;
  }

  return 1;
}

sub delete {
  my $self = shift;
  $self->command( "DELE", @_ );
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

sub auth {
  my $self = shift;
  $self->command( "AUTH", "TLS" );
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

sub pwd {
  my $self = shift;
  my $path;

  $self->command("PWD");
  $self->response();

  if ( ${*$self}{last_ftp_msg} =~ /\"(.*)\".*/ )
  {
    # 257 "/<PATH>/" is current directory.
    # "Quote-doubling" convention - RFC 959, Appendix II
    ( $path = $1 ) =~ s/\"\"/\"/g;
    return $path;
  }
  else {
    return $self->_croak_or_return ();
  }
}

sub cwd {
  my $self = shift;
  $self->command( "CWD", @_ );
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

sub noop {
  my $self = shift;
  $self->command("NOOP");
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

sub rename {
  my $self     = shift;
  my $old_name = shift;
  my $new_name = shift;

  return ( $self->_test_croak ( $self->_rnfr ($old_name) &&
                                $self->_rnto ($new_name) ) );
}

sub cdup {
  my $self = shift;
  $self->command("CDUP");
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

# TODO: Make mkdir() working with recursion.
sub mkdir {
    my $self = shift;
    my $dir = shift;
    $self->command("MKD", $dir);
    return ( $self->_test_croak ($self->response == CMD_OK) );
}

# TODO: Make rmdir() working with recursion.
sub rmdir {
    my $self = shift;
    my $dir = shift;
    $self->command("RMD", $dir);
    return ( $self->_test_croak ($self->response == CMD_OK) );
}

sub site {
  my $self = shift;

  $self->command("SITE", @_);
  return ( $self->_test_croak ($self->response == CMD_OK) );
}

# A true boolean func, should never call croak!
sub supported {
   my $self = shift;
   my $cmd = uc (shift);  # uc() converts undef to "".
   my $site_cmd = uc (shift);

   my $result = 0;        # Assume invalid FTP command

   # It will cache the result so OK to call multiple times.
   my $help = $self->_help ();

   # Only finds exact matches, no abbreviations like some FTP servers allow.
   if (exists $help->{$cmd}) {
      $result = 1;           # Was a valid FTP command
      ${*$self}{last_ftp_msg} = "214 The $cmd command is supported.";
   } else {
      ${*$self}{last_ftp_msg} = "502 Unknown command $cmd.";
   }

   # Are we validating a SITE sub-command?
   if ($result && $cmd eq "SITE" && $site_cmd ne "") {
      my $help2 = $self->_help ($cmd);
      if (exists $help2->{$site_cmd}) {
         ${*$self}{last_ftp_msg} = "214 The $cmd sub-command $site_cmd is supported.";
      } else {
         ${*$self}{last_ftp_msg} = "502 Unknown $cmd sub-command - $site_cmd.";
         $result = 0;     # It failed after all!
      }
   }

   print STDERR "<<+ " . ${*$self}{last_ftp_msg} . "\n" if ${*$self}{debug};

   return ($result);
}

# Allow the user to send a FTP command directly, BE CAREFUL !!
# Since doing unsupported stuff, we can never call croak!

sub quot {
   my $self = shift;
   my $cmd  = uc (shift);

   unless ( $self->supported ($cmd) ) {
      substr (${*$self}{last_ftp_msg}, 0, 1) = CMD_REJECT;
      return (CMD_REJECT);
   }

   # The following FTP commands are known to open a data channel
   if ( $cmd eq "STOR" || $cmd eq "RETR" ||
        $cmd eq "NLST" || $cmd eq "LIST" ||
        $cmd eq "STOU" || $cmd eq "APPE" ) {
      ${*$self}{last_ftp_msg} = "x22 Data Connections not supported via " .
                                "quot().  [$cmd]";
      substr (${*$self}{last_ftp_msg}, 0, 1) = CMD_REJECT;
      print STDERR "<<+ " . ${*$self}{last_ftp_msg} . "\n" if ${*$self}{debug};
      return (CMD_REJECT);
   }

   # You are not allowed to clear the command channel.  It breaks this class!
   if ( $cmd eq "CCC" ) {
      ${*$self}{last_ftp_msg} = "x99 Command CCC is not supported by Net::FTPSSL.";
      substr (${*$self}{last_ftp_msg}, 0, 1) = CMD_REJECT;
      print STDERR "<<+ " . ${*$self}{last_ftp_msg} . "\n" if ${*$self}{debug};
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
  ${*$self}{type} = MODE_ASCII;
  return $self->_test_croak ($self->_type(MODE_ASCII));
}

sub binary {
  my $self = shift;
  ${*$self}{type} = MODE_BINARY;
  return $self->_test_croak ($self->_type(MODE_BINARY));
}

#-----------------------------------------------------------------------
#  Internal functions
#-----------------------------------------------------------------------

sub _user {
  my $self = shift;
  $self->command( "USER", @_ );
  my $resp = $self->response ();
  return ( $resp == CMD_OK || $resp == CMD_MORE );
}

sub _passwd {
  my $self = shift;
  $self->command( "PASS", @_ );
  my $resp = $self->response ();
  return ( $resp == CMD_OK || $resp == CMD_MORE );
}

sub _quit {
  my $self = shift;
  $self->command("QUIT");
  return ( $self->response () == CMD_OK );
}

sub _prot {
  my $self = shift;
  my $opt = shift || ${*$self}{data_prot};

  $self->command( "PROT", $opt );     # C, S, E or P.
  my $resp = ( $self->response () == CMD_OK );

  # Check if someone changed the data channel protection mode ...
  if ($resp && $opt ne ${*$self}{data_prot}) {
    ${*$self}{data_prot} = $opt;   # They did change it!
  }

  return ( $resp );
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

sub _mfmt {
  my $self = shift;
  my $timestamp = shift;  # (stat ($loc_file))[9] - The local file's timestamp!

  # Convert it into YYYYMMDDHHMMSS format (GM Time) [ gmtime() vs localtime() ]
  my ($sec, $min, $hr, $day, $mon, $yr, $wday, $yday, $isdst) =
                  gmtime ( $timestamp );

  my $time = sprintf ("%04d%02d%02d%02d%02d%02d",
                      $yr + 1900, $mon + 1, $day, $hr, $min, $sec);

  $self->command( "MFMT", $time, @_ );
  return ( $self->response () == CMD_OK );
}

sub _mdtm {
  my $self = shift;
  my $timestamp;

  $self->command( "MDTM", @_ );

  if ( $self->response () == CMD_OK &&
       ${*$self}{last_ftp_msg} =~ m/(^|\D)(\d{14})($|\D)/ ) {
    my $time_str = $2;   # The timestamp on the remote server: YYYYMMDDHHMMSS.

    # Now convert it into the internal format used by Perl ...
    $time_str =~ m/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/;
    my ($yr, $mon, $day, $hr, $min, $sec) = ($1 - 1900, $2 - 1, $3, $4, $5, $6);

    # Use GMT Time  [ timegm() vs timelocal() ]
    $timestamp = timegm ( $sec, $min, $hr, $day, $mon, $yr );
  }

  return ( $timestamp );
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
   if ($all_cmds && exists ${*$self}{help_cmds_msg}) {
      ${*$self}{last_ftp_msg} = ${*$self}{help_cmds_msg};
      return ( ${*$self}{help_cmds_found} );

   } elsif (exists ${*$self}{"help_${cmd}_msg"}) {
      ${*$self}{last_ftp_msg} = ${*$self}{"help_${cmd}_msg"};
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
            # Even though not all servers support OPTS as is required with FEAT.
            $help{OPTS} = 1  if ($help{FEAT});     # RFC 2389

            ${*$self}{help_cmds_found} = \%help;
            ${*$self}{help_cmds_msg} = $helpmsg;
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
#  Enable/Disable the Croak logic!
#-----------------------------------------------------------------------

sub set_croak {
   my $self = shift;
   my $turn_on = shift;

   my $res = ${*$self}{Croak} || 0;

   if ( defined $turn_on ) {
      if ( $turn_on ) {
         ${*$self}{Croak} = 1;
      } elsif ( exists ( ${*$self}{Croak} ) ) {
         delete ( ${*$self}{Croak} );
      }
   }

   return ( $res );
}

#-----------------------------------------------------------------------
#  Boolean check for croak!
#  Uses the current message as the croak message on error!
#-----------------------------------------------------------------------

sub _test_croak {
   my $self = shift;
   my $true = shift;

   unless ( $true ) {
      $ERRSTR = ${*$self}{last_ftp_msg};
      if ( ${*$self}{Croak} ) {
         my $c = (caller(1))[3];
         if ( defined $c && $c ne "Net::FTPSSL::login" ) {
            $self->_abort ();
            $self->quit ();
            ${*$self}{last_ftp_msg} = $ERRSTR;
         }

         croak ( $ERRSTR . "\n" );
      }
   }

   return ( $true );
}

#-----------------------------------------------------------------------
#  Error handling - Decides if to Croak or return undef ...
#  Has 2 modes, a regular member func & when not a member ...
#-----------------------------------------------------------------------

sub _croak_or_return {
   my $self = shift;

   # The error code to use if we update the last message!
   # Or if we print it to STDERR & we don't croak!
   my $err = CMD_ERROR . CMD_ERROR . CMD_ERROR;

   unless (defined $self) {
      # Called this way only by new() before $self is created ...
      my $should_we_die = shift;
      my $should_we_print = shift;
      $ERRSTR = shift || "Unknown Error";

      croak ( $ERRSTR . "\n" )   if ( $should_we_die );
      print STDERR "<<+ $err " . $ERRSTR . "\n" if ( $should_we_print );

   } else {
      # Called this way by everyone else ...
      my $replace_mode = shift;  # 1 - append, 0 - replace,
                                 # undef - leave last_message() unchanged
      my $msg = shift;
      $ERRSTR = $msg || ${*$self}{last_ftp_msg};

      # Do 1st so updated if caller trapped the Croak!
      if ( defined $replace_mode && uc ($msg) ne ""  ) {
         if ($replace_mode && uc (${*$self}{last_ftp_msg}) ne "" ) {
            ${*$self}{last_ftp_msg} .= "\n" . $err . " " . $msg;
         } else {
            ${*$self}{last_ftp_msg} = $err . " " . $msg;
         }
      }

      if ( ${*$self}{Croak} ) {
         if ( ref($self) eq "Net::FTPSSL" ) {
            my $tmp = ${*$self}{last_ftp_msg};
            $self->_abort ();
            $self->quit ();
            ${*$self}{last_ftp_msg} = $tmp;
         }

         croak ( $ERRSTR . "\n" );
      }

      if ( defined $replace_mode && uc ($msg) ne ""  ) {
         print STDERR "<<+ $err " . $msg . "\n" if ${*$self}{debug};
      }
   }

   return ( undef );
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

  $data = join( " ",
                map { /\n/
                      ? do { my $n = $_; $n =~ tr/\n/ /; $n }
                      : $_;
                    } @args
              );

  if ( ${*$self}{debug} ) {
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
    my $err_msg = "Can't write command on socket: $!";
    carp "$err_msg";                    # This prints a warning.
    $self->close;
    # Not called as an object member in case $self not a FTPSSL obj.
    return _croak_or_return ($self, 0, $err_msg);
  }

  return 1;
}

# -----------------------------------------------------------------------------
# Some responses take multiple lines to finish. ("211-" vs "211 ")
# Some responses have CR's embeded in them.  (ie: no code in the next line)
# Sometimes the data channel response comes with the open data connection msg.
#     (Especially if the data channel is not encrypted or the file is small.)
# So be careful, you will be blocked if you read past the last row of the
# current response or return the wrong code if you get into the next response!
#     (And will probably hang the next time response() is called.)
# So far the only thing I haven't seen is a call to sysread() returning a
# partial response!
# -----------------------------------------------------------------------------
sub response {
  my $self = shift;
  my ( $data, $code, $sep, $desc ) = ( "", CMD_ERROR, "-", "" );

  ${*$self}{last_ftp_msg} = "";   # Clear out the old message
  my $prefix = ( ref($self) eq "Net::FTPSSL" ) ? "<<< " : "SKT <<< ";

  while ($sep eq "-") {
     if ( exists ${*$self}{next_ftp_msg} ) {
        # The previous call to response() left behind some unprocessed data.
        # So lets use the left over data instead of calling sysread().
        $data = ${*$self}{next_ftp_msg};
        delete ( ${*$self}{next_ftp_msg} );   # No more left over data!
     } else {
        # Now lets read the response from the command channel.
        my $read = sysread( $self, $data, 4096);
        unless( $read ) {
          # Not called as an object member in case $self not a FTPSSL obj.
          _croak_or_return ($self, 0, (defined $read)
                                ? "Can't read command channel socket: $!"
                                : "Unexpected EOF on command channel socket!");
          return (CMD_ERROR);
        }
     }

     # Now lets process the response messages we've read in.  See the comments
     # above this function on why this code is such a mess.
     my @lines = split( "\015\012", $data );
     my $done = 0;
     my $remember = 0;

     foreach my $line ( @lines ) {
       if ( $remember ) {
          # Continuing to save the next response for next time ...
          print STDERR "Saving rest of the next response! ($line)\n"  if ${*$self}{debug};
          ${*$self}{next_ftp_msg} .= "\015\012" . $line;
          next;
       }

#      $data = $self->getline();
#      $data =~ m/^(\d+)(\-?)(.*)$/s;
       $line =~ m/^(\d+)([-\s]?)(.*)$/s;

       my $last_code = $code;
       ($code, $sep, $desc) = ($1, $2, $3);

       if ( $done && defined $sep ) {
          # We read past the end of the current response into the next one ...
          print STDERR "Read past end of response! ($line)\n"   if ${*$self}{debug};
          ${*$self}{next_ftp_msg} = $line;
          $remember = 1;
          $code = $last_code;
          next;
       }
       $code = $last_code  unless ( defined $code );

       print STDERR $prefix . $line . "\n"   if ${*$self}{debug};

       ${*$self}{last_ftp_msg} .= "\n" if ($done);

       ${*$self}{last_ftp_msg} .= $line;

       $done = 1  if (defined $sep && $sep ne '-');

       ${*$self}{last_ftp_msg} .= "\n" unless ($done);
     }

     # Only true if this response message had CR's embeded in it!
     unless (defined $sep) {
        $sep = $done ? " " : "-";   # Final or middle response?
     }
  }

  return substr( $code, 0, 1 );
}

sub last_message {
   my $self = shift;
   return ${*$self}{last_ftp_msg};
}

#-----------------------------------------------------------------------
#  Added to make backwards compatable with Net::FTP
#-----------------------------------------------------------------------
sub message {
   my $self = shift;
   return ${*$self}{last_ftp_msg};
}

#-----------------------------------------------------------------------
# Implements data channel call back functionality ...
#-----------------------------------------------------------------------
sub set_callback {
   my $self = shift;
   my $func_ref = shift;          # The callback function to call.
   my $end_func_ref = shift;      # The end callback function to call.
   my $cb_work_area_ref = shift;  # Optional ref to the callback work area!

   if ( defined $func_ref && defined $end_func_ref ) {
      ${*$self}{callback_func}     = $func_ref;
      ${*$self}{callback_end_func} = $end_func_ref;
      ${*$self}{callback_data}     = $cb_work_area_ref;
   } else {
      delete ( ${*$self}{callback_func} );
      delete ( ${*$self}{callback_end_func} );
      delete ( ${*$self}{callback_data} );
   }

   return;
}

sub _end_callback {
   my $self = shift;
   my $offset = shift;   # Always >= 1.  Index to original function called.
   my $total = shift;

   my $res;
   my $len = 0;

   # Is there an end callback function to use ?
   if ( defined ${*$self}{callback_end_func} ) {
      $res = &{${*$self}{callback_end_func}} ( (caller($offset))[3], $total,
                                               ${*$self}{callback_data} );

      # Now check the results for terminating the call back.
      if (defined $res) {
         if ($res eq "") {
            $res = undef;      # Make it easier to work with.
         } else {
            $len = length ($res);
            $total += $len;
         }
      }
   }

   return ($res, $len, $total);
}

sub _call_callback {
   my $self = shift;
   my $offset = shift;   # Always >= 1.  Index to original function called.

   my $data_ref = shift;
   my $data_len_ref = shift;
   my $total_len = shift;

   # Is there is a callback function to use ?
   if ( defined ${*$self}{callback_func} ) {

      # Allowed to modify contents of $data_ref & $data_len_ref ...
      &{${*$self}{callback_func}} ( (caller($offset))[3],
                                    $data_ref, $data_len_ref, $total_len,
                                    ${*$self}{callback_data} );
   }

   # Calculate the new total length to use for next time ...
   $total_len += (defined $data_len_ref ? ${$data_len_ref} : 0);

   return ($total_len);
}

sub _fmt_num {
   my $self = shift;
   my $num = shift;

   # Change: 1234567890 --> 1,234,567,890
   while ( $num =~ s/(\d)(\d{3}(\D|$))/$1,$2/ ) { }

   return ( $num );
}

#-----------------------------------------------------------------------

1;

__END__

=head1 NAME

Net::FTPSSL - A FTP over SSL/TLS class

=head1 VERSION 0.08

=head1 SYNOPSIS

  use Net::FTPSSL;

  my $ftps = Net::FTPSSL->new('ftp.yoursecureserver.com', 
                              Port => 21,
                              Encryption => EXP_CRYPT,
                              Debug => 1) 
    or die "Can't open ftp.yoursecureserver.com";

  $ftps->login('anonymous', 'user@localhost') 
    or die "Can't login: ", $ftps->last_message();

  $ftps->cwd("/pub") or die "Can't change directory: " . $ftps->last_message;

  $ftps->get("file") or die "Can't get file: " . $ftps->last_message;

  $ftps->quit();

Had you included I<Croak =E<gt> 1> as an option to I<new>, you could have left
off the I<or die> checks and your I<die> messages would be more specific to the
actual problem encountered!

=head1 DESCRIPTION

C<Net::FTPSSL> is a class implementing a simple FTP client over a Secure
Sockets Layer (SSL) or Transport Layer Security (TLS) connection written in
Perl as described in RFC959 and RFC2228.  It will use TLS by default.

=head1 CONSTRUCTOR

=over 4

=item new( HOST [, OPTIONS ] )

Creates a new B<Net::FTPSSL> object and opens a connection with the
C<HOST>. C<HOST> is the address of the FTP server and it's a required
argument. OPTIONS are passed in a hash like fashion, using key and value
pairs.

If it can't create a new B<Net::FTPSSL> object, it will return I<undef> unless
you set the I<Croak> option.  In either case you will find the cause of the
failure in B<$Net::FTPSSL::ERRSTR>.

C<OPTIONS> are:

B<Port> - The port number to connect to on the remote FTP server.
Default value is 21 for B<EXP_CRYPT> and B<CLR_CRYPT> or 990 for B<IMP_CRYPT>.

B<Encryption> - The connection can be implicitly (B<IMP_CRYPT>) encrypted,
explicitly (B<EXP_CRYPT>) encrypted, or regular FTP (B<CLR_CRYPT>).
In explicit cases the connection begins clear and became encrypted after an
"AUTH" command is sent, while implicit starts off encrypted.  For B<CLR_CRYPT>,
the connection never becomes encrypted.  Default value is B<EXP_CRYPT>.

B<DataProtLevel> - The level of security on the data channel.  The default is
B<DATA_PROT_PRIVATE>, where the data is also encrypted. B<DATA_PROT_CLEAR> is
for data sent as clear text.  B<DATA_PROT_SAFE> and B<DATA_PROT_CONFIDENTIAL>
are not currently supported.  If B<CLR_CRYPT> was selected, the data channel
is always B<DATA_PROT_CLEAR>.

B<useSSL> - Use this option to connect to the server using SSL instead of TLS.
TLS is the default encryption type and the more secure of the two protocols.
Set B<useSSL =E<gt> 1> to use SSL.

B<Timeout> - Set a connection timeout value. Default value is 120.

B<PreserveTimestamp> - During all I<puts> and I<gets>, attempt to preserve the
file's timestamp.  By default it will not preserve the timestamps.

B<Buffer> - This is the block size that Net::FTPSSL will use when a transfer is
made. Default value is 10240.

B<Debug> - This turns the debug information option on/off. Default is off.

B<Trace> - Turns on/off put/get download tracing to STDERR.  Default is off.

B<Croak> - Force most methods to call I<croak()> on failure instead of returning
I<FALSE>.  The default is to return I<FALSE> or I<undef> on failure.  When it
croaks, it will attempt to close the FTPS connection as well, preserving the
last message before it attempts to close the connection.  Allowing the server
to know the client is going away.  This will cause I<$Net::FTPSSL::ERRSTR> to
be set as well.

B<SSL_Advanced> - Expects a reference to a hash.  This feature is totally
unsupported.  It is only provided so you can attempt to use the more obscure
options when start_SSL() is called.  If an option here conflicts with other
options we would normally use, entries in this hash take precedence.  See
I<IO::Socket::SSL> for these options.

=back

=head1 METHODS

Most of the methods return I<true> or I<false>, true when the operation was
a success and false when failed. Methods like B<list> or B<nlst> return an
empty array when they fail.  This behavior can be modified by the B<Croak>
option.

=over 4

=item login( USER, PASSWORD )

Use the given information to log into the FTP server.

=item list( [DIRECTORY [, PATTERN]] )

This method returns a list of files in a format simalar to this: (Server Specific)

 drwxrwx--- 1 owner group          512 May 31 11:16 .
 drwxrwx--- 1 owner group          512 May 31 11:16 ..
 drwxrwx--- 1 owner group          512 Oct 27  2004 foo
 drwxrwx--- 1 owner group          512 Oct 27  2004 pub
 drwxrwx--- 1 owner group          512 Mar 29 12:09 bar

If I<DIRECTORY> is omitted, the method will return the list of the current
directory.

If I<PATTERN> is provided, it would limit the result similar to the unix I<ls>
command and the Windows Command Window I<dir> command.  The only wild cards
supported are B<*> and B<?>.  (Match 0 or more chars.  Or any one char.)
So a pattern of I<f*>, I<?oo> or I<FOO> would find just I<foo> from the list
above.  Files with spaces in their name can cause strange results when searching
for a pattern.

=item nlst( [DIRECTORY [, PATTERN]] )

Same as C<list> but returns the list in this format:

 foo
 pub
 bar

Personally, I suggest using list instead of nlst.

=item ascii()

Sets the file transfer mode to ASCII.  I<CR LF> transformations will be done.

=item binary()

Sets the file transfer mode to binary. No transformation will be done.

=item get( REMOTE_FILE, [LOCAL_FILE] )

Retrieves the I<REMOTE_FILE> from the ftp server. I<LOCAL_FILE> may be a
filename or a filehandle.  Return B<undef> if it fails.

If the option I<PreserveTimestamp> was used, and the FTPS server supports it,
it will attempt to reset the timestamp on I<LOCAL_FILE> to the timestamp on
I<REMOTE_FILE>.

=item put( LOCAL_FILE, [REMOTE_FILE] )

Stores the I<LOCAL_FILE> onto the remote ftp server. I<LOCAL_FILE> may be a
filehandle, but in this case I<REMOTE_FILE> is required.
Return B<undef> if it fails.

If the option I<PreserveTimestamp> was used, and the FTPS server supports it,
it will attempt to reset the timestamp on I<REMOTE_FILE> to the timestamp on
I<LOCAL_FILE>.

=item uput( LOCAL_FILE, [REMOTE_FILE] )

Stores the I<LOCAL_FILE> onto the remote ftp server. I<LOCAL_FILE> may be a
filehandle, but in this case I<REMOTE_FILE> is required.  If I<REMOTE_FILE>
already exists on the ftp server, a unique name is calculated for use instead.

If the file transfer succeeds, this function will return the actual name used
on the remote ftps server.  If it can't figure that out, it will return what
was used for I<REMOTE_FILE>.  On failure this method will return B<undef>.

If the option I<PreserveTimestamp> was used, and the FTPS server supports it,
it will attempt to reset the timestamp on the remote file using the file name
being returned by this function to the timestamp on I<LOCAL_FILE>.  So if the
wrong name is being returned, the wrong file will get it's timestamp updated.

=item xput( LOCAL_FILE, [REMOTE_FILE, [PREFIX, [POSTFIX, [BODY]]]] )

Use when the directory you are dropping I<REMOTE_FILE> into is monitored by
a file recognizer that might pick the file up before the file transfer has
completed.  So the file is transferred using a temporary name using a naming
convention that the file recognizer will ignore and is guaranteed to be unique.
Once the file transfer successfully completes, it will be I<renamed> to
I<REMOTE_FILE> for immediate pickup by the file recognizer.  If you requested
to preserve the file's timestamp, this step is done after the file is renamed
and so can't be 100% guaranteed if the file recognizer picks it up first. But
if it was done before the rename, other more serious problems could crop up.

On failure this function will attempt to I<delete> the scratch file for you if
its at all possible.  You will have to talk to your FTP server administrator on
good values for I<PREFIX> and I<POSTFIX> if the defaults are no good for you.

B<PREFIX> defaults to I<_tmp.> unless you override it.  Set to "" if you need
to suppress the I<PREFIX>.  This I<PREFIX> can be a path to another directory
if needed, but that directory must already exist!  Set to I<undef> to keep this
default and you need to change the default for I<POSTFIX> or I<BODY>.

B<POSTFIX> defaults to I<.tmp> unless you override it.  Set to "" if you need
to suppress the I<POSTFIX>.  Set to I<undef> to keep this default and you need
to change the default for I<BODY>.

B<BODY> defaults to I<client-name.PID> so that you are guaranteed the temp file
will have an unique name on the FTP server.  It is strongly recommended that
you don't override this value.

So the temp scratch file would be called something like this by default:
S<I<_tmp.testclient.51243.tmp>>.

=item delete( REMOTE_FILE )

Deletes the indicated I<REMOTE_FILE>.

=item cwd( DIR )

Attempts to change directory to the directory given in I<DIR>.

=item pwd()

Returns the full pathname of the current directory.

=item cdup()

Changes directory to the parent of the current directory.

=item mkdir( DIR )

Creates the indicated directory I<DIR>. No recursion at the moment.

=item rmdir( DIR )

Removes the empty indicated directory I<DIR>. No recursion at the moment.

=item noop()

It specifies no action other than the server send an OK reply.

=item rename( OLD, NEW )

Allows you to rename the file on the server.

=item site( ARGS )

Send a SITE command to the remote server and wait for a response.

=item supported( CMD [,SITE_OPT] )

Returns TRUE if the remote server supports the given command.  I<CMD> must match
exactly.  If the I<CMD> is SITE and I<SITE_OPT> is supplied, it will also check
if the specified I<SITE_OPT> sub-command is supported.  Not all servers will
support the use of I<SITE_OPT>.  This function ignores the B<Croak> request.

=item quot( CMD [,ARGS] )

Send a command, that Net::FTPSSL does not directly support, to the remote
server and wait for a response.

Returns the most significant digit of the response code.  So it will ignore
the B<Croak> request.

B<WARNING> This call should only be used on commands that do not require
data connections.  Misuse of this method can hang the connection if the
internal list of FTP commands using a data channel is incomplete.

=item last_message() or message()

Use either one to collect the last response from the FTP server.  This is the
same response printed to I<STDERR> when trace is turned on.  It may also contain
any fatal error message encountered.

If you couldn't create a I<Net::FTPSSL> object, you should get your error
message from I<$Net::FTPSSL::ERRSTR> instead.

=item set_croak( [1/0] )

Used to turn the I<Croak> option on/off after the Net::FTPSSL object has been
created.  It returns the previous I<Croak> settings before the change is made.
If you don't provide an argument, all it does is return the current setting.
Provided in case the I<Croak> option proves to be too restrictive in some cases.

=item set_callback( [cb_func_ref, end_cb_func_ref [, cb_data_ref]] )

This function allows the user to define a callback function to use whenever a
data channel to the server is open.  If either B<cb_func_ref> or
B<end_cb_func_ref> is undefined, it disables the callback functionality, since
both are required for call backs to function properly.

The B<cb_func_ref> is a reference to a function to handle processing the
data channel data.  This is a I<void> function that can be called multiple
times.  It is called each time a chunk of data is read from or written to the
data channel.

The B<end_cb_func_ref> is a reference to a function to handle closing the
callback for this data channel connection.  This function is allowed to return
a string of additional data to process before the data channel is closed.  It
is called only once per command after processing all the data channel data.

The B<cb_data_ref> is an optional reference to an I<array> or I<hash> that the
caller can use to store values between calls to the callback function and the
end callback function.  If you don't need such a work area, it's safe to not
provide one.  The Net::FTPSSL class doesn't look at this reference.

The callback function must take the following B<5> arguments:

   B<callback> (ftps_func_name, data_ref, data_len_ref, total_len, cb_data_ref);

The I<ftps_func_name> will tell what Net::FTPSSL function requested the callback
so that your I<callback> function can determine what the data is for and do
conditional logic accordingly.  We don't provide a reference to the Net::FTPSSL
object itself since the class is not recursive.  Each Net::FTPSSL object should
have it's own I<cb_dat_ref> to work with.  But methods within the class can
share one.

Since we pass the data going through the data channel as a reference, you are
allowed to modify the data.  But if you do, be sure to update I<data_len_ref>
to the new data length as well.  Otherwise you will get buggy responses.

Finally, the I<total_len> is how many bytes have already been processed.  It
does not include the data passed for the current I<callback> call.  So it will
always be zero the first time it's called.

Once we finish processing data for the data channel, a different callback
function will be called to tell you that the data channel is closing.  This is
your last chance to affect what is going over the data channel and to do any
needed post processing.  The end callback function must take the following
arguments:

   $end = B<end_callback> (ftps_func_name, total_len, cb_data_ref);

These arguments have the same meaning as for the callback function, except that
this function allows you to optionally provide additional data to/from the data
channel.  If reading from the data channel, it will treat the return value as
the last data returned before it was closed.  Otherwise it will be written to
the data channel before it is closed.  Please return I<undef> if there is
nothing extra for the Net::FTPSSL command to process.

You should also take care to clean up the contents of I<cb_data_ref> in the
I<end_callback> function.  Otherwise the next callback sequence that uses this
work area may behave strangely.

As a final note, should the data channel be empty, it is likely that just the
I<end_callback> function is called without any calls to the I<callback>
function.

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

Copyright (c) 2005 Marco Dalla Stella. All rights reserved.

Copyright (c) 2009 Curtis Leach. All rights reserved.

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

