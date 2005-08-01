# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-FTPSSL.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 4;
BEGIN { use_ok('Net::FTPSSL') }

my( $address, $server, $port, $user, $pass, $mode ); 

print "\tServer address ( host[:port] ): ";
chop( $address = <STDIN> );

print "\tConnection mode (I)mplicit or (E)xplicit. Default 'E': ";
chop( $mode = <STDIN> );

print "\tUser (default 'anonymous'): ";
chop( $user = <STDIN> );

print "\tPassword (default 'user\@localhost'): ";
chop( $pass = <STDIN> );

( $server, $port ) = split( /:/, $address );
$port = 21 unless $port;
$mode = EXP_CRYPT unless $mode =~ /(I|E)/;
$user = 'anonymous' unless $user;
$pass = 'user@localhost' unless $pass;

SKIP: {
  skip 'Server address not defined', 4 unless $server;
  my $ftp =
    Net::FTPSSL->new( $server, port => $port, encryption => $mode )
    or die "Can't open $server:$port";

  isa_ok( $ftp, 'Net::FTPSSL', 'Net::FTP object creation' );

  ok( $ftp->login( $user, $pass ), 'Login' );

  ok( scalar $ftp->list() != 0, 'list() command (PASV() command worked too!)' );

  $ftp->quit();
}

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
# vim:ft=perl:
