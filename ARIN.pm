package Net::Whois::ARIN;
# $Id: ARIN.pm,v 1.23 2003/08/30 20:49:11 tcaine Exp $

use strict;

use vars qw/ $VERSION /;
$VERSION = '0.03';

use Carp;
use IO::Socket;

sub new {
    my $class = ref($_[0]) ? ref(shift) : shift;
    my %param = @_;
    my %args;

    foreach (keys %param) {
        if    (/^-?host(?:name)?$/i) { $args{'host'}    = $param{$_} }
        elsif (/^-?port$/i)          { $args{'port'}    = $param{$_} }
        elsif (/^-?timeout$/i)       { $args{'timeout'} = $param{$_} }
        elsif (/^-?retries$/i)       { $args{'retries'} = $param{$_} }
        else { 
            carp("$_ is not a valid argument to ${class}->new()");
        }
    }

    my $self = bless {
        '_host'    => $args{'host'} || 'whois.arin.net',
        '_port'    => $args{'port'} || 43,
        '_timeout' => $args{'timeout'},
        '_retries' => $args{'retries'} || 3,
    }, ref $class || $class;

    return $self;
}

#  connect to a whois server
sub _connect {
    my $self = shift;
    my $host = $self->{'_host'};
    my $port = $self->{'_port'};
    my $retries = $self->{'_retries'};
    my $sock = undef;

    do {
        $sock = IO::Socket::INET->new(
            PeerHost => $host,
            PeerPort => $port,
            Proto    => 'tcp',
            ( ( defined $self->{'_timeout'} )
                ? ('Timeout' => $self->{'_timeout'})
                : (),
            ),
        )
    } while (!$sock && --$retries);
 
    unless ($sock) {
        my $error = $@;
        if($error eq 'IO::Socket::INET: ') {
            $error = 'connection time out';
        }
        croak "Can't connect to $host\[$port\]: $error";
    }

    $sock->autoflush();
    return $sock;
}

#  open connection, send a whois query, close connection, return whois response
sub query {
    my($self, $query) = @_;
    my $s = $self->_connect();
    print $s '' . $query . "\x0d\x0a";
    local $/;
    my $results = <$s>;
    undef $s;
    return (wantarray) ? split(/\n/, $results) : $results;
}

sub _parse_record {
    my @output = @_;
    my (%record, %fields);
    foreach (@output) {
        if(my($key, $value) = $_ =~ /^(\S+):\s+(.*)$/) {
            $value =~ s/\s*$//;
            if ($fields{$key}) { $record{$key} .= "\n$value" }
            else               { $record{$key}  = $value }
            $fields{$key} ++;
        }
    }
    return %record;
}

sub net {
    my ($self, $query) = @_;
    my @output  = $self->query("n + $query");
    my @records;
    my $n = -1;
    foreach (@output) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;
        $records[++$n] = {} if $key eq 'OrgName' || $key eq 'CustName';
        $records[$n]->{$key} = $value;
    }
    return @records;
}

*network = \&net;

sub asn {
    my ($self, $query) = @_;
    my @output  = $self->query("a + $query");
    my %record  = _parse_record(@output);
    return (wantarray) ? %record : \%record;
}

sub org {
    my ($self, $query) = @_;
    my @output  = $self->query("o + $query");
    my @records;
    my %fields;
    my $n = -1;
    foreach (@output) {
        next unless(my ($key, $value) = $_ =~ /^(\S+):\s+(.*)$/);
        $value =~ s/\s*$//;
        $records[++$n] = {} if /^OrgName:/;
        if ($fields{$key}) { $records[$n]->{$key} .= "\n$value" }
        else               { $records[$n]->{$key}  = $value }
        $fields{$key} ++;
    }
    if ($query =~ /^!/) {
        return (wantarray) ? %{$records[$n]} : $records[$n];
    }
    return @records;
}

*organization = \&org;

sub cust {
    my ($self, $query, $handle) = @_;
    my @output  = $self->query("c + $query");
    my @records;
    my $n = -1;
    foreach (@output) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;
        $records[++$n] = {} if /^CustName:/;
        $records[$n]->{$key} = $value;
    }
    return @records;
}

*customer = \&cust;

sub poc {
    my ($self, $query) = @_;
    my @output  = $self->query("p + $query");
    return _parse_record(@output);
}

sub handle {
    my ($self, $query) = @_;
    my @output = $self->query("!$query");
    my %record = _parse_record(@output);
    return (wantarray) ? %record : \%record;
}

sub domain {
    my ($self, $query) = @_;
    $query = "\@$query" if $query !~ /^\@/;
    my @output = $self->query($query);
    my @results = ([undef, undef, undef, undef]);
    foreach (@output) {
         if(/^Name:\s+(.*)$/) {
             $results[0]->[0] = $1;
         }
         elsif(/^Handle:\s+(.*)$/) {
             $results[0]->[1] = $1;
         }
         elsif(/^Phone:\s+(.*)$/) {
             unless (exists $results[0]->[3]) {
                 $results[0]->[3] = $1;
             }
         }
         elsif(/^Email:\s+(.*)$/) {
             $results[0]->[2] = $1;
             last;
         }
    }
    return @results;
}

1;
__END__

=head1 NAME

Net::Whois::ARIN - client interface to the ARIN Whois server

=head1 SYNOPSIS

  use Net::Whois::ARIN;

  my $w = Net::Whois::ARIN->new;

  my $result = $w->query( '207.173.112.1' );

  my @results = $w->query( 'NET-207-173-112-0-1' );

  my @output = $w->net( '207.173.112.0' );
  foreach my $r (@output) {
      printf(
          "%s\t(%s)\t%s\n",
          $r->{'OrgName'},
          $r->{'NetHandle'},
          $r->{'NetRange'}
      );
  }

  my %asn = $w->asn( 5650 );
  printf "AS5650 was assigned to %s\n", $asn{'OrgName'};
  printf "The email address for AS5650's technical point of contact is %s\n", $asn{'TechEmail'};

  my %poc = $w->poc('DM2339-ARIN');

  my %org = $w->org('!ELIX');

  my @records = $w->domain('eli.net');

  my %handle = $w->handle('DM2339-ARIN');

  my @customers = $w->customer('ELIX');

=head1 DESCRIPTION

This module provides a Perl interface to the ARIN Whois server.  The module takes care of connecting to a whois server, sending your whois requests, and parsing the whois output.  The whois records are returned as a hash.  In cases where more that one record is found a list of hashes are returned instead.

=head1 METHODS

In the calling conventions below C<[]>'s represent optional parameters.

=over 4

=item B<new> - create a Net::Whois::ARIN object

  my $o = Net::Whois::ARIN->new(
    [-hostname=> 'whois.arin.net',]
    [-port    => 43,]
    [-timeout => 45,]
  );

This is the constuctor for Net::Whois::ARIN.  The object returned can be used to query the whois database.

=item B<net> - request a network record

  my @records = $o->net('207.173.112.0');

This method requires a single argument.  The argument indicates the network to use in the whois lookup.  The method returns a list of network records that matched your search criteria.

=item B<asn> - request an ASN record

  my %record = $o->asn(5650);

This method requires a single argument.  The argument indicates the autonomous system number to us in the whois lookup.  The method returns a point-of-contact record as a hash.  If the search criteria matches more than one record a list of hashes are returned instead.  Searching ASN records by ASN always returns a single record.  Just don't expect $o->asn('Network') to return a single record.

=item B<poc> - request a POC record

  my %record = $w->poc('DM2339-ARIN');

=item B<org> - request an organization record

  my %record = $w->org('!ELIX');

=item B<customer> - request a customer record

  my @records = $w->customer('ELIX');

=item B<domain> - request all records from a given domain

  @output = $w->domain('eli.net');

=item B<handle> - request a specific record using a whois handle

  %record = $w->handle('DM2339-ARIN');

By querying the database using a handle you are guarenteed to get one record back since handles are always unique in the ARIN whois database.  This is analogous to prepending your query with an "!" character.

=back

=head1 AUTHOR

Todd Caine   <todd at pobox.com>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2002, 2003 Todd Caine.  All rights reserved. This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
