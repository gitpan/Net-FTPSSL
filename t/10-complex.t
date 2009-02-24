# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl ./t/10-complex.t'

#########################

use strict;

use Test::More tests => 33;

# plan tests => 32;  # Can't use due to BEGIN block

BEGIN { use_ok('Net::FTPSSL') }    # Test # 1

# Delete test files from previous run
unlink ("./t/test_file_new.tar.gz",
        "./t/FTPSSL.pm_new.tst",
        "./t/test_trace_log_new.txt");

sleep (1);  # So test 1 completes before the message prints!

diag( "\nYou can also perform a deeper test." );
diag( "Some information will be required for this test:" );
diag( "A secure ftp server address, a user, a password and a directory" );
diag( "where the user has permissions to read and write." );
my $more_test = ask_yesno("Do you want to make a deeper test");

SKIP: {
    skip "Deeper test skipped for some reason...", 32 unless $more_test;

    my( $address, $server, $port, $user, $pass, $dir, $mode, $data, $encrypt_mode ); 

    $address = ask("Server address ( host[:port] )");

    $user = ask("\tUser (default 'anonymous')");

    $pass = ask("\tPassword (default 'user\@localhost')");

    $dir = ask("\tDirectory (default <HOME>)");

    $mode = uc (ask("\tConnection mode (I)mplicit or (E)xplicit. (default 'E')"));

    $data = uc (ask("\tData Connection mode (C)lear or (P)rotected. (default 'P')"));

    $encrypt_mode = uc (ask("\tUse (T)LS or (S)SL encryption (Default 'T')"));

    ( $server, $port ) = split( /:/, $address );
    $port = 21 unless $port;
    $mode = EXP_CRYPT unless $mode =~ /^(I|E)$/;
    $data = DATA_PROT_PRIVATE unless $data =~ /^(C|S|E|P)$/;
    $user = 'anonymous' unless $user;
    $pass = 'user@localhost' unless $pass;
    $encrypt_mode = ($encrypt_mode eq "S") ? 1 : 0;

    # -----------------------------------------------------------
    # End of user interaction ...
    # -----------------------------------------------------------

    my %callback_hash;

    # So we can save the Debug trace in a file from this test.
    open (OLDERR, ">&STDERR");
    open (STDERR, "> ./t/test_trace_log_new.txt");

    my $ftp = Net::FTPSSL->new( $server, Port => $port, Encryption => $mode,
                                DataProtLevel => $data,
                                useSSL => $encrypt_mode,
                                Debug => 1, Trace => 1, Croak => 1 );

    isa_ok( $ftp, 'Net::FTPSSL', 'Net::FTPSSL object creation' );

    ok( $ftp->login ($user, $pass), "Login to $server" );

    $dir = $ftp->pwd ()  unless $dir;   # Ask for HOME dir if not provided!

    ok( $ftp->cwd( $dir ), "Changed the dir to $dir" );
    my $pwd = $ftp->pwd();
    ok( defined $pwd, "Getting the directory: ($pwd)" );

    # Turning off croak now that our environment is correct!
    $ftp->set_croak (0);

    my $res = $ftp->cdup ();
    $pwd = $ftp->pwd();
    ok ( $res, "Going up one level: ($pwd)" );

    $res = $ftp->cwd ( $dir );
    $pwd = $ftp->pwd();
    ok ( $res, "Returning to proper dir: ($pwd)" );

    # Verifying supported() & _help() work as expected.
    # Must check logs for _help() success, since returns a hash reference.

    ok( $ftp->supported("HELP"), "Checking if HELP is supported" );
    ok( $ftp->_help("HELP"), "Getting the HELP usage" );  # Never fails
    print STDERR "--- " . $ftp->last_message() . " ---\n";

    ok( $ftp->_help("HELP"), "Getting the HELP usage again (cached?)" );
    print STDERR "--- " . $ftp->last_message() . " -- (cached?) --\n";

    ok( $ftp->supported("HELP"), "Checking HELP supported again (cached?)" );
    ok( ! $ftp->supported("BADCMD"), "Verifying BADCMD isn't supported" );
    ok( ! $ftp->supported("SITE", "BADCMD"), "Verifying SITE BADCMD isn't supported" );

    # Verifying we can check out valid SITE sub-commands ...
    # Returns hash ref of valid SITE commands
    my $site = $ftp->_help ("SITE");
    if (scalar (keys %{$site}) > 0) {
       my @sites = sort (keys %{$site});
       ok( $ftp->supported("SITE", $sites[0]), "Verifying SITE $sites[0] is supported" );
    } else {
       ok( 0, "verifying \"supported ('SITE', <cmd>)\" is supported!  List of SITE cmds available" );
    }

    ok( $ftp->noop(), "Noop test" );

    # -----------------------------------------------
    # Start put/uput/get/rename/delete section ...
    # -----------------------------------------------

    ok( $ftp->put( './FTPSSL.pm' ), "puting a test ascii file on $dir" );

    # So the supported test will appear in the log file 1st!
    $res = $ftp->supported ("STOU");
    my $uput_name = $ftp->uput ( './FTPSSL.pm' );

    if ($res) {
       ok( $uput_name, "uput the same test ascii file again as: $uput_name" );
       if ( $uput_name ne "FTPSSL.pm" ) {
          ok( $ftp->delete($uput_name), "deleting $uput_name on $server" );
       } else {
          ok( 0, "Did we correctly detect new uput name used? ($uput_name)" );
       }
    } else {
       ok( ! $uput_name, "uput should fail since STOU not supported on this server" );
       ok ( 1, "uput delete skiped since uput not supported!" );
    }

    ok( $ftp->binary (), 'putting FTP in binry mode' );
    ok( $ftp->put( './t/test_file.tar.gz' ), "puting a test binary file on $dir" );

    # Query after put() call so there is something to find!
    # (Otherwise it looks like it may have failed.)
    my @lst = $ftp->list ();
    ok( scalar @lst != 0, 'list() command' );
    print_result (\@lst);

    $ftp->set_callback (\&callback_func, \&end_callback_func, \%callback_hash);
    @lst = $ftp->list ();
    ok( scalar @lst != 0, 'list() command with callback' );
    print_result (\@lst);
    $ftp->set_callback ();   # Disable callbacks again

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

    # With call back
    $ftp->set_callback (\&callback_func, \&end_callback_func, \%callback_hash);
    @lst = $ftp->nlst ();
    ok( scalar @lst != 0, 'nlst() command with callback' );
    print_result (\@lst);
    $ftp->set_callback ();   # Disable callbacks again

    # Without call back
    @lst = $ftp->nlst ();
    ok( scalar @lst != 0, 'nlst() command' );
    print_result (\@lst);

    ok( $ftp->get($file, './t/test_file_new.tar.gz'), 'retrieving the binary file' );
    ok( $ftp->delete($file), "deleting the test bin file on $server" );
    ok ( -s './t/test_file.tar.gz' == -s './t/test_file_new.tar.gz', "Verifying BINARY file matches original size" );

    ok( $ftp->ascii (), 'putting FTP back in ascii mode' );
    ok( $ftp->get("FTPSSL.pm", './t/FTPSSL.pm_new.tst'), 'retrieving the ascii file again' );
    ok( $ftp->delete("FTPSSL.pm"), "deleting the test file on $server" );
    ok ( -s './FTPSSL.pm' == -s './t/FTPSSL.pm_new.tst', "Verifying ASCII file matches original size" );

    $file = "delete_me_I_do_not_exist.txt";
    ok ( ! $ftp->get ($file), "Get a non-existant file!");
    my $del = glob ($file);
    my $size = -s $file;
    unlink ($file);
    if ($del) {
       print STDERR " *** Deleted local file: $del  [$size byte(s)].\n";
    }

    # -----------------------------------------
    # End put/get/rename/delete section ...
    # -----------------------------------------

    $ftp->quit();

    # Restore STDERR now that the tests are done!
    open (STDERR, ">&OLDERR");
    if (1 == 2) {
       print OLDERR "\n";   # Perl gives warning if not present!  (Not executed)
    }
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

# Save the results from the list() & nlst() calls.
# Remember that STDERR should be redirected to a log file by now.
sub print_result {
   my $lst = shift;

   # Tell the max number of entries you may print out.
   # Just in case the list is huge!
   my $cnt = 4;

   my $max = scalar (@{$lst});
   print STDERR "------------- Found $max file(s) -----------------\n";
   foreach (@{$lst}) {
      if ($cnt <= 0) {
         print STDERR "...\n";
         print STDERR "($lst->[-1])\n";
         last;
      }
      print STDERR "($_)\n";
      --$cnt;
   }
   print STDERR "-----------------------------------------------\n";
}

# Testing out the call back functionality of v0.07.
sub callback_func {
   my $ftps_function_name = shift;
   my $data_ref     = shift;      # The data to/from the data channel.
   my $data_len_ref = shift;      # The size of the data buffer.
   my $total_len    = shift;      # The number of bytes to date.
   my $callback_data_ref = shift; # The callback work space.

   if ( $ftps_function_name =~ m/:list$/ ) {
      ${$data_ref} =~ s/[a-z]/\U$&/g;    # Convert to upper case!
      # Format #'s Ex: 1234567 into 1,234,567.
      while ( ${$data_ref} =~ s/(\d)(\d{3}\D)/$1,$2/ ) { }
      ${$data_len_ref} = length (${$data_ref});  # Changed length of data!

   } elsif ( $ftps_function_name =~ m/:nlst$/ ) {
      ${$data_ref} =~ s/[a-z]/\U$&/g;    # Convert to upper case!
      ${$data_ref} =~ s/^/[0]: /gm;      # Add a prefix per line.

      # Make the prefix unique per line ...
      my $cnt = ++$callback_data_ref->{counter};
      while ( ${$data_ref} =~ s/\[0\]/[$cnt]/) {
         $cnt = ++$callback_data_ref->{counter};
      }

      # Fix so counter is correct for next time called!
      --$callback_data_ref->{counter};

      ${$data_len_ref} = length (${$data_ref});  # Changed length of data!

   } else {
      print STDERR " *** Unexpected callback for $ftps_function_name! ***\n";
   }

   return ();
}

# Testing out the end call back functionality of v0.07.
sub end_callback_func {
   my $ftps_function_name = shift;
   my $total_len          = shift;  # The total number of bytes sent out
   my $callback_data_ref = shift;   # The callback work space.

   my $tail;   # Additional data channel data to provide ...

   if ( $ftps_function_name =~ m/:nlst$/ ) {
      my $cnt;
      my $sep = "";
      $tail = "";
      foreach ("Junker", "T-Bird", "Coup", "Model-T", "Horse & Buggy") {
         $cnt = ++$callback_data_ref->{counter};
         $tail .= $sep . "[$cnt]: $_!";
         $sep = "\n";
      }

      # So the next nlst call will start counting all over again!
      delete ($callback_data_ref->{counter});
   }

   return ( $tail );
}

# vim:ft=perl:

