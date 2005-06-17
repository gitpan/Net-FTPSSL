# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-FTPSSL.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More qw( no_plan );
BEGIN { use_ok('Net::FTPSSL') }

ok(1);

my $ftp =
  Net::FTPSSL->new( 'ftp.autistici.org', port => 21, encryption => EXP_CRYPT )
  or die "Can't open ftp.autistici.org";

isa_ok( $ftp, 'Net::FTPSSL', 'Object creation' );

ok( $ftp->login( 'anonymous', 'user@localhost' ), 'Login' );

ok( scalar $ftp->list() != 0, 'list() command' );

$ftp->quit();

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
# vim:ft=perl:
