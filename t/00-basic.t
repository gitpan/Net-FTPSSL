#!/usr/bin/perl -w

use Test::More tests => 2;
# plan tests => 1;

BEGIN { use_ok('Net::FTPSSL') }

ok(1, 'Net::FTPSSL loaded.');

diag( "\nNet::FTPSSL loaded properly." );

# vim:ft=perl:
