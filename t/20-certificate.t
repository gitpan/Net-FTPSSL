# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl ./t/10-complex.t'

#########################

# Goal here is to give as many success messagse as possible.
# Especially when not all FTP servers support all functions.
# So the logic here can be a bit convoluted.

use strict;
use warnings;

# Uncomment if you need to trace issues with IO::Socket:SSL methods as well.
# Proper values are: debug0, debug1, debug2 & debug3.  3 is the most verbose!
use IO::Socket::SSL qw(debug3);

use Test::More tests => 11;   # Also update skipper (one less)
use File::Copy;

my $skipper = 10;

# plan tests => 10;  # Can't use due to BEGIN block

BEGIN { use_ok('Net::FTPSSL') }    # Test # 1

sleep (1);  # So test 1 completes before the message prints!

# -----------------------------------------------------------
# This section initializes a new feature to Net::FTPSSL.
# It's required in order to implement Client Certificates
# so that you can talk to FTPS servers that require them.
# -----------------------------------------------------------
# **** THIS IS THE CODE SECTION TO MODIFY. ****
# **** SEE THE README FILE FOR INSTRUCTIONS ON THE 3 LINES ****
# **** OF CODE YOU NEED TO CHANGE BELOW TO BE ABLE TO TALK ****
# **** TO YOUR FTPS SERVER USING CLIENT CERTIFICATES! ****
# -----------------------------------------------------------
my %certificate_hash = ( SSL_version   => "SSLv23",
                         SSL_use_cert  => 1,
                         SSL_server    => 0,
                         SSL_key_file  => "$ENV{HOME}/Certificate/private.pem",
                         SSL_cert_file => "$ENV{HOME}/Certificate/pubkey.pem",
                         SSL_passwd_cb => sub { return ("my_password") },
                         Timeout       => 60 );
# -----------------------------------------------------------
# **** END OF SECTION TO CUSTOMIZE! ****
# -----------------------------------------------------------


diag( "" );
diag( "\nYou can also perform a certificate test." );
diag( "Some information will be required for this test:" );
diag( "A secure ftp server expecting a client certificate,");
diag( "a user, a password and a directory where the user");
diag( "has permissions to read and write." );
diag ( "See the README file for instructions on how to fully" );
diag ( "enable this test!" );

my $p_flag = proxy_supported ();

my $more_test = ask_yesno("Do you want to do a certificate test");

SKIP: {
    skip ( "Certificate tests skipped for some reason ...", $skipper ) unless $more_test;

    unless (-f $certificate_hash{SSL_key_file} && -f $certificate_hash{SSL_cert_file} ) {
       skip ( "Deeper test skipped due to no client certificate defined ...", $skipper );
    }

    my( $address, $server, $port, $user, $pass, $dir, $mode, $data, $encrypt_mode, $psv_mode ); 

    $address = ask2("Server address ( host[:port] )", undef, undef, $ENV{FTPSSL_SERVER});
    ( $server, $port ) = split( /:/, $address );
    # $port = 21 unless $port;   # Let FTPSSL provide the default port.
    $port = "" unless (defined $port);

    $user = ask2("\tUser", "anonymous", undef, $ENV{FTPSSL_USER});

    $pass = ask2("\tPassword [a space for no password]", "user\@localhost", undef, $ENV{FTPSSL_PWD});

    $dir = ask2("\tDirectory", "<HOME>", undef, $ENV{FTPSSL_DIR});
    $dir = "" if ($dir eq "<HOME>");   # Will ask server for it later on.

    $mode = ask("\tConnection mode (I)mplicit or (E)xplicit.",
                EXP_CRYPT, "(I|E)");

    if ( $mode eq CLR_CRYPT ) {
       $data = $encrypt_mode = "";   # Make sure not undef ...
    } else {
       $data = ask("\tData Connection mode (C)lear or (P)rotected.",
                   DATA_PROT_PRIVATE, "(C|S|E|P)");

       $encrypt_mode = ask("\tUse (T)LS or (S)SL encryption", "T", "(T|S)");
    }
    $encrypt_mode = ($encrypt_mode eq "S") ? 1 : 0;

    $psv_mode = ask("\tUse (P)ASV or (E)PSV for data connections", "P", "(P|E)");

    my $proxy;
    $proxy = ask_proxy_questions ()  if ($p_flag);


    # The main certificate log file ...
    my $log_file = "./t/test_certificate.txt";

    # -----------------------------------------------------------
    # End of user interaction ...
    # -----------------------------------------------------------

    # Delete test files from previous run
    unlink ($log_file);

    # So we can save the Debug trace in a file from this test.
    # We don't use DebugLogFile for this on purpose so that everything
    # written to STDERR is in the log file, including msgs from this test!
    # But doing it this way is very undesireable in a real program!
    open (OLDERR, ">&STDERR");
    open (STDERR, "> $log_file");

    $certificate_hash{SSL_version} = ($encrypt_mode ? "SSLv23" : "TLSv1");

    # My Net::FTPSSL connection options ...
    my %ftps_opts = ( Port => $port, Encryption => $mode,
                      DataProtLevel => $data, useSSL => $encrypt_mode,
                      SSL_Client_Certificate => \%certificate_hash,
                      Croak => 1,
                      Timeout => 121, Debug => 1, Trace => 1 );

    # Set if we are going through a proxy server ...
    if (defined $proxy) {
       $ftps_opts{ProxyArgs} = $proxy;
    }

    print STDERR "\n**** Starting the Certificate server test ****\n";

    # Writes logs to STDERR which this script redirects to a file ...
    my $ftp = Net::FTPSSL->new( $server, \%ftps_opts );

    isa_ok( $ftp, 'Net::FTPSSL', 'Net::FTPSSL object creation' );

    ok( $ftp->login ($user, $pass), "Login to $server" );

    # Turning off croak now that our environment is correct!
    $ftp->set_croak (0);

    if ( $psv_mode eq "P" ) {
       ok ( 1, "Using PASV mode for data connections" );
    } else {
       my $t = $ftp->force_epsv (1);
       $psv_mode = $t ? "1" : "2";
       $t = $ftp->force_epsv (2)  unless ( $t );
       ok ( $t, "Force Extended Passive Mode (EPSV $psv_mode)" );
       unless ( $t ) {
          --$skipper;
          skip ( "EPSV not supported, please rerun test using PASV instead!", $skipper );
       }
    }

    # Ask for the user's HOME dir if it's not provided!
    $dir = $ftp->pwd ()  unless ($dir);

    # -------------------------------------------------------------------------
    # Back to processing the real test cases ...
    # -------------------------------------------------------------------------
    ok( $ftp->cwd( $dir ), "Changed the dir to $dir" );
    my $pwd = $ftp->pwd();
    ok( defined $pwd, "Getting the directory: ($pwd)" );
    $dir = $pwd  if (defined $pwd);     # Convert relative to absolute path.

    my $res = $ftp->cdup ();
    $pwd = $ftp->pwd();
    ok ( $res, "Going up one level: ($pwd)" );

    # $res = $ftp->cwd ( $dir );
    # $pwd = $ftp->pwd();
    # ok ( $res, "Returning to proper dir: ($pwd)" );

    ok( $ftp->noop(), "Noop test" );

    my @lst;
    @lst = $ftp->nlst ();
    ok( scalar @lst != 0, 'nlst() command' );
    print_result (\@lst);

    @lst = $ftp->list ();
    ok( scalar @lst != 0, 'list() command' );
    print_result (\@lst);

    # -----------------------------------------
    # Closing the connection ...
    # -----------------------------------------

    ok( $ftp->quit(), 'quit() command' );

    # Free so any context messages will still appear in the log file.
    $ftp = undef;

    # Restore STDERR now that the tests are done!
    open (STDERR, ">&OLDERR");
    if (1 == 2) {
       print OLDERR "\n";   # Perl gives warning if not present!  (Not executed)
    }
}

# =====================================================================
# Start of subroutines ...
# =====================================================================

# Does an automatic shift to upper case for all answers
sub ask {
  my $question = shift;
  my $default  = uc (shift);
  my $values   = uc (shift);

  my $answer = uc (prompt ($question, $default, $values));

  if ( $values && $answer !~ m/^$values$/ ) {
     $answer = $default;   # Change invalid value to default answer!
  }

  # diag ("ANS: [$answer]");

  return $answer;
}

# This version doesn't do an automatic upshift
# Also provides a way to enter "" as a valid value!
# The Alternate Default is from an optional environment variable
sub ask2 {
  my $question = shift;
  my $default  = shift || "";
  my $values   = shift || "";
  my $altdef   = shift || $default;

  my $answer = prompt ($question, $altdef, $values);

  if ( $answer =~ m/^\s+$/ ) {
     $answer = "";         # Overriding any defaults ...
  } elsif ( $values && $answer !~ m/^$values$/ ) {
     $answer = $altdef;    # Change invalid value to default answer!
  }

  # diag ("ANS2: [$answer]");

  return $answer;
}

sub ask_yesno {
  my $question = shift;

  my $answer = prompt ($question, "N", "(Y|N)");

  # diag ("ANS-YN: [$answer]");

  return $answer =~ /^y(es)*$/i ? 1 : 0;
}

# Save the results from the list() & nlst() calls.
# Remember that STDERR should be redirected to a log file by now.
sub print_result {
   my $lst = shift;

   # Tell the max number of entries you may print out.
   # Just in case the list is huge!
   my $cnt = 5;

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


# Based on ExtUtils::MakeMaker::prompt
# (can't use since "make test" doesn't display questions!)

sub prompt {
   my ($question, $def, $opts) = (shift, shift, shift);

   my $isa_tty = -t STDIN && (-t STDOUT || !(-f STDOUT || -c STDOUT));

   my $dispdef = defined $def ? "[$def] " : " ";
   $def = defined $def ? $def : "";

   if (defined $opts && $opts !~ m/^\s*$/) {
      diag ("\n$question ? $opts $dispdef");
   } else {
      diag ("\n$question ? $dispdef");
   }

   my $ans;
   if ( $ENV{PERL_MM_USE_DEFAULT} || (!$isa_tty && eof STDIN)) {
      diag ("$def\n");
   } else {
      $ans = <STDIN>;
      chomp ($ans);
      unless (defined $ans) {
         diag ("\n");
      }
   }

   $ans = $def  unless ($ans);

   return ( $ans );
}

# Check if using a proxy server is supported ...
sub proxy_supported {
   eval {
      require Net::HTTPTunnel;
   };
   if ($@) {
      diag ("NOTE: Using a proxy server is not supported without first installing Net::HTTPTunnel\n");
      return 0;
   }

   return 1;
}

# Ask the proxy server related questions ...
sub ask_proxy_questions {
   my $ans = ask_yesno ("Will you be FTP'ing through a proxy server?");
   unless ($ans) {
      return undef;
   }

   my %proxy_args;
   $proxy_args{'proxy-host'} = ask2 ("\tEnter your proxy server name", undef, undef, $ENV{FTPSSL_PROXY_HOST});
   $proxy_args{'proxy-port'} = ask2 ("\tEnter your proxy port", undef, undef, $ENV{FTPSSL_PROXY_PORT});
   $ans = ask2 ("\tEnter your proxy user name (or space if not required)", undef, undef, $ENV{FTPSSL_PROXY_USER});
   if ($ans ne "") {
      $proxy_args{'proxy-user'} = $ans;
      $proxy_args{'proxy-pass'} = ask2 ("\tEnter your proxy password", undef, undef, $ENV{FTPSSL_PROXY_PWD});
   }

   # diag ("Host: ", $proxy_args{'proxy-host'}, "   Port: ", $proxy_args{'proxy-port'}, "  User: ", ($proxy_args{'proxy-user'} || "undef"), "  Pwd: ", ($proxy_args{'proxy-pwd'} || "undef"));

   return \%proxy_args;
}

# vim:ft=perl:

