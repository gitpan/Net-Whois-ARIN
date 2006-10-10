use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'		=> 'Net::Whois::ARIN',
    'VERSION_FROM'	=> 'lib/Net/Whois/ARIN.pm', # finds $VERSION
    'PREREQ_PM'		=> { 
                               'IO::Socket::INET'   => 0, 
                               'Test::More'         => 0, 
                               'Test::MockObject'   => 0, 
                           },
    (($] ge '5.005') ?
        (   'AUTHOR'   => 'Todd Caine <todd.caine@gmail.com>',
            'ABSTRACT' => 'ARIN whois client',
        ) : (),
    ),
);
