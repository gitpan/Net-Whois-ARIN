
use Test::More tests => 13;

BEGIN { use_ok( 'Net::Whois::ARIN' ); }

my $w = Net::Whois::ARIN->new(
    -hostname=> 'whois.arin.net',
    -port    => 43,
    -timeout => 45,
);

isa_ok($w, 'Net::Whois::ARIN');

my $result = $w->query('207.173.112.1');
ok($result, 'got a response from the whois server');

my @results = $w->query('NET-207-173-112-0-1');
ok(@results > 1, 'got a response from the whois server');

my @output = $w->net('207.173.112.0');
ok(@output == 1, 'one result for net 207.173.112.0');

my %asn_rec = $w->asn(5650);
ok(exists $asn_rec{'ASNumber'}, 'lookup on ASN 5650 is valid');

my %poc_rec = $w->poc('DM2339-ARIN');
ok(exists $poc_rec{'Name'}, 'POC record for DM2339-ARIN is valid');

my %org_rec = $w->org('!ELIX');
ok(exists $org_rec{'OrgName'}, 'one org record for handle ELIX');

@output = $w->org('ELIX');
ok(@output == 1, 'one org record for ELIX');

@output = $w->domain('eli.net');
ok(@output, 'valid domain query');

@output = $w->domain('foobar.com');
ok(@output, 'single valid domain query');

my %handle_rec = $w->handle('DM2339-ARIN');
is($handle_rec{'Handle'}, 'DM2339-ARIN', 'handle() received the correct handle');

my @cust_rec = $w->customer('ELIX');
ok(!@cust_rec, 'returned undef because of bogus query');

