#!/usr/bin/perl -w

use Test::More;
plan tests => 1;

BEGIN { use_ok('Net::FTPSSL') }

ok(1, 'Net::FTPSSL loaded.');

diag( "\nNet::FTPSSL loaded properly." );

# vim:ft=perl:
