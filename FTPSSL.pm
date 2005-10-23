# File	  : Net::FTPSSL
# Author  : kral <kral at paranici dot org>
# Created : 01 March 2005
# Version : 0.04
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

$VERSION = "0.04";
@EXPORT  = qw( IMP_CRYPT EXP_CRYPT );

use constant IMP_CRYPT => "I";
use constant EXP_CRYPT => "E";

use constant CMD_INFO    => 1;
use constant CMD_OK      => 2;
use constant CMD_MORE    => 3;
use constant CMD_REJECT  => 4;
use constant CMD_ERROR   => 5;
use constant CMD_PENDING => 0;
use constant MODE_BINARY => "I";
use constant MODE_ASCII  => "A";

sub new {
  my $self         = shift;
  my $type         = ref($self) || $self;
  my $host         = shift;
  my %arg          = @_;
  my $port         = $arg{Port} || 'ftp(21)';
  my $debug        = $arg{Debug} || 0;
  my $timeout      = $arg{Timeout} || 120;
  my $buf_size     = $arg{Buffer} || 10240;
  my $encrypt_mode = $arg{Encryption} || EXP_CRYPT;
  my $clear_sock;

  croak "Host undefined" unless $host;

  croak "Encryption mode unknow!"
    if ( $encrypt_mode ne IMP_CRYPT && $encrypt_mode ne EXP_CRYPT );

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

  # In explicit mode, FTPSSL send an AUTH SSL command, catch the messages
  # and then transform the clear connection in a crypted one.
  # TODO: Let the user select the encryption type. (SSL, TLS)
  if ( $encrypt_mode eq EXP_CRYPT ) {
    return undef unless ( response($socket) == CMD_OK );
    command( $socket, "AUTH", "TLS" );
    response($socket);
  }
	
  # Turn the clear connection in a SSL one.
  my $obj = $type->start_SSL( $socket, SSL_version => "TLSv1" )
    or croak IO::Socket::SSL::errstr();

  # This is made for catch the banner when the connection
  # is implicitly crypted.
  if ( $encrypt_mode eq IMP_CRYPT ) {
    return undef unless ( response($socket) == CMD_OK );
  }

  ${*$obj}{'debug'}    = $debug;
  ${*$obj}{'timeout'}  = $timeout;
  ${*$obj}{'buf_size'} = $buf_size;
  ${*$obj}{'type'}     = 'A';

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
  $self->_protp();

  $self->command("PASV");
  my $msg = $self->getline();

  print "<<< " . $msg if ${*$self}{'debug'};

  unless ( substr( $msg, 0, 1 ) == CMD_OK ) { return 0; }

  $msg =~ m/(\d+)\s(.*)\(((\d+,?)+)\)\.?/
    ;    # [227] [Entering Passive Mode] ([h1,h2,h3,h4,p1,p2]).

  my @address = split( /,/, $3 );

  my $host = join( '.', @address[ 0 .. 3 ] );
  my $port = $address[4] * 256 + $address[5];

  my $socket = Net::SSLeay::Handle->make_socket( $host, $port )
    or croak "Can't open $host:$port";

  unless ($socket) { croak "Can't open $host:$port"; }

  ${*$self}{'data_ch'} = \*$socket;

  return 1;
}

sub list {
  my $self = shift;
  my $path = shift;
  my ( $tmp, $dati, $io, $size );

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( $self->_list($path) ) {

    $size = ${*$self}{'buf_size'};
    $io   = new IO::Handle;
    tie( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

	$io->autoflush(1);

    while ( my $len = sysread $io, $tmp, $size ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on read while list(): $!\n";
      }
      $dati .= $tmp;
    }
  }

  $io->close();
  $self->response;    # For catch "226 Closing data connection."

  return $dati ? split( /\n/, $dati ) : ();
}

sub nlst {
  my $self = shift;
  my $path = shift;
  my ( $tmp, $dati, $io, $size );

  unless ( $self->pasv() ) {
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( $self->_nlst($path) ) {

    $size = ${*$self}{'buf_size'};

    $io = new IO::Handle;
    tie( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

    $io->autoflush(1);

    while ( my $len = sysread $io, $tmp, $size ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on read while nlst(): $!\n";
      }
      $dati .= $tmp;
    }
  }

  $io->close();
  $self->response;    # For catch "226 Closing data connection."

  return $dati ? split( /\n/, $dati ) : ();
}

sub get {
  my $self     = shift;
  my $file_rem = shift;
  my $file_loc = shift;
  my ( $size, $localfd );

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
  }

  if ( ${*$self}{'type'} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
  }

  if ( $self->_retr($file_rem) ) {
    my ( $data, $written );
    my $io = new IO::Handle;
    tie( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

    $io->autoflush(1);

    while ( ( my $len = sysread $io, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on get(): $!\n";
      }
      $written = syswrite $localfd, $data, $len;
      croak "System write error on get(): $!\n" unless defined $written;
    }

    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;
  }

  return undef;
}

sub put {
  my $self     = shift;
  my $file_loc = shift;
  my $file_rem = shift;
  my ( $size, $localfd );

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
  }

  unless ($file_rem) {
    require File::Basename;
    $file_rem = File::Basename::basename($file_loc);
  }

  if ( ${*$self}{'type'} eq MODE_BINARY ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
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

    my ( $data, $written );
    my $io = new IO::Handle;
    tie( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

    $io->autoflush(1);

    while ( ( my $len = sysread $localfd, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on put(): $!\n";
      }
      $written = syswrite $io, $data, $len;
      croak "System write error on put(): $!\n" unless defined $written;
    }

    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;

  }

  return undef;
}

sub uput {              # Unique put (STOU command)
  my $self     = shift;
  my $file_loc = shift;
  my $file_rem = shift;
  my ( $size, $localfd );

  $size = ${*$self}{'buf_size'} || 2048;

  unless ( $self->pasv() ) {
    $self->_abort();
    croak "Can't set passive mode!: " . ${*$self}{'last_ftp_msg'};
  }

  if ( ref($file_loc) && ref($file_loc) eq "GLOB" ) {
    $localfd = \*$file_loc;
  }
  else {
    unless ( open( $localfd, "< $file_loc" ) ) {
      $self->_abort();
      croak "Can't open local file!";
    }
  }

  if ( ${*$self}{'type'} eq 'I' ) {
    unless ( binmode $localfd ) {
      $self->_abort();
      croak "Can't set binary mode to local file!";
    }
  }

  unless ( defined ${*$self}{'alloc_size'} ) {
    if ( -f $file_loc ) {
      my $size = -s $file_loc;
      $self->alloc($size);
    }
  }

  delete ${*$self}{'alloc_size'};

  if ( $self->_stou($file_rem) ) {

    my ( $data, $written );
    my $io = new IO::Handle;
    tie( *$io, "Net::SSLeay::Handle", ${*$self}{'data_ch'} );

    $io->autoflush(1);

    while ( ( my $len = sysread $localfd, $data, $size ) ) {
      unless ( defined $len ) {
        next if $! == EINTR;
        croak "System read error on put(): $!\n";
      }
      $written = syswrite $io, $data, $len;
      croak "System write error on put(): $!\n" unless defined $written;
    }

    $io->close();
    $self->response;    # For catch "226 Closing data connection."
    return 1;

  }

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
  my $args = shift;

  $self->command("SITE", $args);
  return ( $self->response == CMD_OK );
}

#-----------------------------------------------------------------------
#  Type setting function
#-----------------------------------------------------------------------

sub ascii {
  my $self = shift;
  ${*$self}{'type'} = MODE_ASCII;
  return $self->_type('A');
}

sub binary {
  my $self = shift;
  ${*$self}{'type'} = MODE_BINARY;
  return $self->_type('I');
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

sub _protp {
  my $self = shift;
  $self->command( "PROT", "P" );
  return ( $self->response == CMD_OK );
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
#  Messages handler
#-----------------------------------------------------------------------

sub command {
  my $self = shift;
  my @args;
  my $data;

  @args = grep defined($_), @_
    ; # remove undef values from the list. Maybe I have to find out why those undef were passed.
  $data = join(
    " ",
    map {
      /\n/
        ? do { my $n = $_; $n =~ tr/\n/ /; $n }
        : $_;
      } @args
  );

  $data .= "\015\012";

  print STDERR ">>> " . $data
    if ref($self) eq "Net::FTPSSL" && ${*$self}{'debug'};

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

sub response {
  my $self = shift;
  my ( $data, $code );

	my $read = sysread( $self, $data, 4096);
	unless( defined $read ) {
		croak "Can't read on socket: $!";
	}

	my @lines = split( "\015\012", $data );
		
  foreach my $line ( @lines ) {

# 	$data = $self->getline();	
#   $data =~ m/^(\d+)(\-?)(.*)$/s;
    $line =~ m/^(\d+)(\-?)(.*)$/s;

    $code = $1;
    print STDERR "<<< " . $line ."\n"
      if ref($self) eq "Net::FTPSSL" && ${*$self}{'debug'};

    if ( ref($self) eq "Net::FTPSSL" ) {
      ${*$self}{'last_ftp_msg'} = $line;
    }

    last if $2 ne '-';

  }

  return substr( $code, 0, 1 );

}

sub last_message {
  my $self = shift;
  return ${*$self}{'last_ftp_msg'};
}

1;

__END__

=head1 NAME

Net::FTPSSL - A FTP over SSL/TLS class

=head1 VERSION 0.04

=head1 SYNOPSIS

  use Net::FTPSSL;

  my $ftps = Net::FTPSSL->new('ftp.yoursecureserver.com', 
                              Port => 21,
                              Encryption => 'E',
                              Debug => 1) 
    or die "Can't open ftp.yoursecureserver.com";

  $ftps->login('anonymous', 'user@localhost') 
    or die "Can't login: ", $ftps->$last_message();

  $ftps->cwd("/pub") or die "Can't change directory: ", $ftps->last_message;

  $ftps->get("file") or die "Can't get file: ", $ftps->last_message;

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
Default value is 21.

B<Encryption> - The connection can be implicitly (B<IMP_CRYPT>) or
explicitly (B<EXP_CRYPT>) encrypted.
In explicit cases the connection begins clear and became encrypted after an
"AUTH" command is sent. Default value is EXP_CRYPT.

B<Timeout> - Set a connection timeout value. Default value is 120.

B<Buffer> - This is the block size that Net::FTPSSL will use when a transfer is
made. Default value is 10240.

B<Debug> - This set the debug informations option on/off. Default is off.

=back

=head1 METHODS

All the methods return I<true> or I<false>, true when the operation was
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

=item get(REMOTE_FILE, LOCAL_FILE)

Retrives the REMOTE_FILE from the ftp server. LOCAL_FILE may be a filename or a
filehandle.	Return undef if it fails.

=item put(LOCAL_FILE, [REMOTE_FILE])

Stores the LOCAL_FILE into the remote ftp server. LOCAL_FILE may be filehandle,
but in this case REMOTE_FILE is required. Return undef if it fails.

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

=back

=head1 AUTHOR

Marco Dalla Stella - <kral at paranoici dot org>

=head1 SEE ALSO

L<Net::Cmd>

L<Net::FTP>

L<Net::SSLeay::Handle>

L<IO::Socket::SSL>

RFC 2228 - L<ftp://ftp.rfc-editor.org/in-notes/rfc2228.txt>

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
