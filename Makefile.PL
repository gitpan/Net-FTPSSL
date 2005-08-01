use 5.006001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Net::FTPSSL',
    VERSION_FROM      => 'FTPSSL.pm', # finds $VERSION
    PREREQ_PM         => { IO::Socket::SSL => 0.0, Net::SSLeay::Handle => 0.0 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'FTPSSL.pm', # retrieve abstract from module
       AUTHOR         => 'Marco Dalla Stella <kral at paranoici dot org>') : ()),
);
