#!/usr/local/bin/perl -w

use strict;

use Data::Dumper;
use XML::Simple;

use Net::Whois::ARIN;

my $o = Net::Whois::ARIN->new;

#  display raw whois output
print "\n\nRaw Whois output:\n";
print join "\n", $o->query('!ELIX');

my %rec = $o->handle('ELIX');

print "Data::Dumper output:\n";
print Data::Dumper->Dump([\%rec], ['Record']);

#  display XML whois output
print "\n\nXML output:\n";
print XMLout(
    \%rec,
    xmldecl        => 1,
    noattr         => 1,
    rootname       => 'Record',
    suppressempty  => undef,
);

