use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::Whois::ARIN',
    'VERSION_FROM'	=> 'ARIN.pm', # finds $VERSION
    'PREREQ_PM'		=> {},
    (($] ge '5.005') ?
        (   'AUTHOR'   => 'Todd Caine <todd@pobox.com>',
            'ABSTRACT' => 'interface to ARIN whois',
        ) : (),
    ),
);
