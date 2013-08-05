use 5.006001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my $value = prompt ("Will you be tunneling through a proxy server?  This requires extra modules.", "Y");

# My list of required modules for Net::FTPSSL ...
my %req = ( IO::Socket::SSL => 1.08, IO::Socket::INET => 0.0, Net::SSLeay::Handle => 0.0,
            File::Basename => 0.0, File::Copy => 0.0, Time::Local => 0.0, Sys::Hostname => 0.0 );

# Also required if you need to go through a proxy tunnel ...
if ($value eq "Y" || $value eq "y") {
   $req{"Net::HTTPTunnel"} = 0.50;
}

WriteMakefile(
    NAME              => 'Net::FTPSSL',
    VERSION_FROM      => 'FTPSSL.pm',         # finds $VERSION
                                              # e.g., Module::Name => 1.1
    PREREQ_PM         => \%req,

    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'FTPSSL.pm',         # retrieve abstract from module
       AUTHOR         => 'Curtis Leach <cleach at cpan dot org>') : ()),
);

