#!/usr/bin/perl -w

use Test::More tests => 3;
# plan tests => 2;

BEGIN { use_ok('Net::FTPSSL') }

ok(1, 'Net::FTPSSL loaded.');

my $res = test_caller ();
ok ($res, "Verifying caller func available for use in FTPSSL");

# if ($res) {
#    diag( "\nNet::FTPSSL loaded properly." );
# } else {
#    diag("\nNet::FTPSSL loaded properly, but will have issues with caller().");
# }


# Tells us early on if the current version of perl doesn't support this.
# Means that the caller logic in FTPSSL won't work if this test fails!
# Done since I'm developing & testing with perl v5.8.8 only.
sub test_caller {
   return ( (caller(0))[3] eq "main::test_caller" &&
            uc ((caller(1))[3]) eq "" &&
            test2 ( (caller(0))[3] ) &&
            Zapper123::ztest1 ( (caller(0))[3] ) );
}

sub test2 {
   return ( (caller(1))[3] eq $_[0] && (caller(0))[3] eq "main::test2" );
}

package Zapper123;

sub ztest1 {
   return ( (caller(1))[3] eq $_[0] &&
            (caller(0))[3] eq "Zapper123::ztest1" &&
            main::test2 ( (caller(0))[3] ) );
}

# vim:ft=perl:
