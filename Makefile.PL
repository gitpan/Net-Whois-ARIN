use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::Whois::ARIN',
    'VERSION_FROM'	=> 'lib/Net/Whois/ARIN.pm', # finds $VERSION
    'PREREQ_PM'		=> { 'IO::Socket' => 0, 'Test::More' => 0, 'Class::MethodMaker' => 0 },
    (($] ge '5.005') ?
        (   'AUTHOR'   => 'Todd Caine <todd@pobox.com>',
            'ABSTRACT' => 'interface to ARIN whois',
        ) : (),
    ),
);
