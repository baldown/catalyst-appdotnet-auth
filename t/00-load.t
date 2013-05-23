#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Catalyst::Authentication::Credential::OAuth2::AppDotNet' ) || print "Bail out!\n";
}

diag( "Testing Catalyst::Authentication::Credential::OAuth2::AppDotNet $Catalyst::Authentication::Credential::OAuth2::AppDotNet::VERSION, Perl $], $^X" );
