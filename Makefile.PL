use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'		=> 'Net::Whois::ARIN',
    'VERSION_FROM'	=> 'lib/Net/Whois/ARIN.pm', # finds $VERSION
    'PREREQ_PM'		=> { 
                               'Class::MethodMaker' => 0,
                               'IO::Socket::INET'   => 0, 
                               'Test::More'         => 0, 
                           },
    (($] ge '5.005') ?
        (   'AUTHOR'   => 'Todd Caine <todd@pobox.com>',
            'ABSTRACT' => 'interface to ARIN whois',
        ) : (),
    ),
);
