use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Catalyst::Authentication::Credential::OAuth2::AppDotNet',
    AUTHOR           => q{Josh Ballard <josh@oofle.com>},
    VERSION_FROM     => 'lib/Catalyst/Authentication/Credential/OAuth2/AppDotNet.pm',
    ABSTRACT_FROM    => 'lib/Catalyst/Authentication/Credential/OAuth2/AppDotNet.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
        'Catalyst::Authentication::Credential::OAuth2' =>  0.001002,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Catalyst-Authentication-Credential-OAuth2-AppDotNet-*' },
);
