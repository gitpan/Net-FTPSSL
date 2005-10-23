# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-FTPSSL.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';
use strict;
use Test::More;

plan tests => 8;

BEGIN { use_ok('Net::FTPSSL') }

diag( "\nYou can also perform a deeper test." );
diag( "Some informations will be required for this test:" );
diag( "A secure ftp server address, a user, a password and a directory" );
diag( "where the user has permissions to read and write." );
my $more_test = ask_yesno("Do you want to make a deeper test");

SKIP: {
	skip "Deeper test skipped for some reason...", 8 unless $more_test;

	my( $address, $server, $port, $user, $pass, $mode, $dir ); 

	$address = ask("Server address ( host[:port] )");

	$mode = ask("\tConnection mode (I)mplicit or (E)xplicit. (default 'E')");

	$user = ask("\tUser (default 'anonymous')");

	$pass = ask("\tPassword (default 'user\@localhost')");
	
	$dir = ask("\tDirectory (default \/)");

	( $server, $port ) = split( /:/, $address );
	$port = 21 unless $port;
	$mode = EXP_CRYPT unless $mode =~ /(I|E)/;
	$user = 'anonymous' unless $user;
	$pass = 'user@localhost' unless $pass;

  my $ftp =
    Net::FTPSSL->new( $server, Port => $port, Encryption => $mode )
    or die "Can't open $server:$port";

  isa_ok( $ftp, 'Net::FTPSSL', 'Net::FTP object creation' );

  ok( $ftp->login( $user, $pass ), 'Login' );

	ok( $ftp->cwd( $dir ), "Changed the dir to $dir" );

  ok( scalar $ftp->list() != 0, 'list() command' );

	ok( $ftp->put( './t/test_file.tar.gz' ), 'puting a test file on $dir' );
	ok( $ftp->rename('test_file.tar.gz', 'test_file_new.tar.gz'), 'renaming it' );
	ok( $ftp->get('test_file_new.tar.gz', './t/test_file_new.tar.gz'), 'getting the renamed file' );
	ok( $ftp->delete('test_file_new.tar.gz'), 'deleting the test file' );

  $ftp->quit();
}

sub ask {
  my $question = shift;
  diag("\n$question ? ");

  my $answer = <STDIN>;
  chomp $answer;
  return $answer;
}

sub ask_yesno {

  my $question = shift;
  diag("\n$question ? [y/N]");

  my $answer = <STDIN>;
  chomp $answer;
  return $answer =~ /^y(es)*$/i ? 1 : 0;
}

# vim:ft=perl:
