# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-FTPSSL.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';
use strict;

use Test::More tests => 22;

# plan tests => 21;  # Can't use due to BEGIN block

BEGIN { use_ok('Net::FTPSSL') }    # Test # 1

# Delete test files from previous run
unlink ("./t/test_file_new.tar.gz",
        "./t/FTPSSL.pm_new.tst",
        "./t/test_list_results_new.txt",
        "./t/test_trace_log_new.txt");

diag( "\nYou can also perform a deeper test." );
diag( "Some informations will be required for this test:" );
diag( "A secure ftp server address, a user, a password and a directory" );
diag( "where the user has permissions to read and write." );
my $more_test = ask_yesno("Do you want to make a deeper test");

SKIP: {
    skip "Deeper test skipped for some reason...", 21 unless $more_test;

    my( $address, $server, $port, $user, $pass, $mode, $dir ); 

    $address = ask("Server address ( host[:port] )");

    $mode = uc (ask("\tConnection mode (I)mplicit or (E)xplicit. (default 'E')"));

    $user = ask("\tUser (default 'anonymous')");

    $pass = ask("\tPassword (default 'user\@localhost')");

    $dir = ask("\tDirectory (default \/)");

    ( $server, $port ) = split( /:/, $address );
    $port = 21 unless $port;
    $mode = EXP_CRYPT unless $mode =~ /^(I|E)$/;
    $user = 'anonymous' unless $user;
    $pass = 'user@localhost' unless $pass;

    # So we can save the Debug trace in a file from this test.
    open (OLDERR, ">&STDERR");
    open (STDERR, "> ./t/test_trace_log_new.txt");

    my $ftp =
      Net::FTPSSL->new( $server, Port => $port, Encryption => $mode, Debug => 1, Trace => 1 )
          or die "Can't open $server:$port";

    isa_ok( $ftp, 'Net::FTPSSL', 'Net::FTPSSL object creation' );

    ok( $ftp->login( $user, $pass ), "Login to $server" );

    ok( $ftp->cwd( $dir ), "Changed the dir to $dir" );
    my $pwd = $ftp->pwd();
    ok( defined $pwd, "Getting the directory: ($pwd)" );

    my $res = $ftp->cdup ();
    my $pwd = $ftp->pwd();
    ok ( $res, "Going up one level: ($pwd)" );

    my $res = $ftp->cwd ( $dir );
    my $pwd = $ftp->pwd();
    ok ( $res, "Returning to proper dir: ($pwd)" );

    ok( $ftp->supported("HELP"), "Checking if HELP is supported" );
    ok( ! $ftp->supported("BADCMD"), "Verifying BADCMD isn't supported" );

    ok( $ftp->noop(), "Noop test" );

    ok( $ftp->put( './FTPSSL.pm' ), "puting a test ascii file on $dir" );

    if ($ftp->supported ("STOU")) {
       ok( $ftp->uput( './FTPSSL.pm' ), "uput the same test ascii file again" );
    } else {
       ok( ! $ftp->uput( './FTPSSL.pm' ), "uput should fail since STOU not supported on this server" );
    }

    ok( $ftp->binary (), 'putting FTP in binry mode' );
    ok( $ftp->put( './t/test_file.tar.gz' ), "puting a test binary file on $dir" );

    # Put after put() call so there is something to find!
    # (Otherwise it looks like it failed.)
    my @lst = $ftp->list ();
    ok( scalar @lst != 0, 'list() command' );

    # -----------------------------------
    # Check if the rename fails, since that will affect the remaining tests ...
    # Possible reasons: Command not supported or your account doesn't have
    # permission to do the rename!
    # -----------------------------------
    $res = $ftp->rename ('test_file.tar.gz', 'test_file_new.tar.gz');
    my $msg = $ftp->last_message();      # If it failed, find out why ...
    if ($ftp->supported ("RNFR") && $ftp->supported ("RNTO")) {
       if ($res) {
          ok( $res, 'renaming bin file works' );
       } else {
          ok( ($msg =~ m/Permission denied/) || ($msg =~ m/^550 /),
              "renaming bin file check: ($msg)" );
       }
    } else {
       ok( ! $res, "Rename is not supported on this server" );
    }
    my $file = $res ? "test_file_new.tar.gz" : "test_file.tar.gz";

    my @lst2 = $ftp->nlst ();
    ok( scalar @lst2 != 0, 'nlst() command' );

    ok( $ftp->get($file, './t/test_file_new.tar.gz'), 'retrieving the binary file' );
    ok( $ftp->delete($file), "deleting the test bin file on $server" );

    ok( $ftp->ascii (), 'putting FTP back in ascii mode' );
    ok( $ftp->get("FTPSSL.pm", './t/FTPSSL.pm_new.tst'), 'retrieving the ascii file again' );
    ok( $ftp->delete("FTPSSL.pm"), "deleting the test file on $server" );
    # -----------------------------------

    $ftp->quit();

    # Restore STDERR now that the tests are done!
    open (STDERR, ">&OLDERR");
    if (1 == 2) {
       print OLDERR "\n";   # Perl gives warning if not present!
    }

    # Save the results from the list() & nlst() calls.
    open (TMP, "> ./t/test_list_results_new.txt");
    print TMP "Dir: ($pwd)\n";
    foreach (@lst, @lst2) {
       print TMP "($_)\n";
    }
    close (TMP);
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

