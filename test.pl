
use Test::More tests => 26;

use_ok( 'Net::Whois::ARIN' );

my $w = Net::Whois::ARIN->new(
    -hostname=> 'whois.arin.net',
    -port    => 43,
    -timeout => 45,
);

isa_ok($w, 'Net::Whois::ARIN');

my $result = $w->query('207.173.0.0');
ok($result, 'got a response from the whois server');

my @results = $w->query('NET-207-173-0-0-1');
ok(@results > 1, 'got a response from the whois server');

my @output = $w->network('207.173.0.0');
ok(@output == 1, 'one result for net 207.173.0.0');
isa_ok($output[0], 'Net::Whois::ARIN::Network');

my @contacts = $output[0]->contacts;
is(scalar(@contacts), 5, 'AS5650 has 5 point-of-contacts');
isa_ok $_, 'Net::Whois::ARIN::Contact' for @contacts;

my $as = $w->asn(5650);
isa_ok($as, 'Net::Whois::ARIN::AS');
is($as->ASNumber, 5650, 'lookup on AS5650 returned AS5650');

@contacts = $as->contacts;
is(scalar(@contacts), 3, 'AS5650 has 3 point-of-contacts');
isa_ok $_, 'Net::Whois::ARIN::Contact' for @contacts;

my @contact = $w->contact('Caine, Todd');
ok(@contact > 0, 'POC records found for Caine, Todd');

@contact = $w->contact('TCA53-ARIN');
isa_ok($contact[0], 'Net::Whois::ARIN::Contact');

my @org = $w->organization('ELIX');
isa_ok($org[0], 'Net::Whois::ARIN::Organization');
ok($org[0]->OrgName, 'one org record for handle ELIX');

@output = $w->domain('eli.net');
$DB::single ++;
ok(@output, 'valid domain query');

@output = $w->domain('foobar.com');
ok(@output, 'single valid domain query');

my @cust = $w->customer('Internet and Telephone');
isa_ok($cust[0], 'Net::Whois::ARIN::Customer');
ok(@cust, 'valid customer query');

