package Net::Whois::ARIN;
# $Id: ARIN.pm,v 1.18 2004/05/14 22:43:26 tcaine Exp $

=pod 

=head1 NAME

Net::Whois::ARIN - client interface to the ARIN Whois server

=head1 SYNOPSIS

  use Net::Whois::ARIN;

  my $w = Net::Whois::ARIN->new(
              host    => 'whois.arin.net',
              port    => 43,
              timeout => 30,
          );

  #  fetch raw whois output as a list
  my $result = $w->query( '207.173.0.0' );

  #  fetch raw whois output as a scalar
  my @results = $w->query( 'NET-207-173-0-0-1' );

  #  get Net::Whois::ARIN::Network records
  my @output = $w->network( '207.173.0.0' );
  foreach my $net (@output) {
      printf(
          "%s\t(%s)\t%s\n",
          $net->OrgName,
          $net->NetHandle,
          $net->NetRange,
      );
  }

  my($asn) = $w->asn( 5650 );
  printf "AS5650 was assigned to %s\n", $asn->OrgName;
  printf "The email address for AS5650's technical point of contact is %s\n", $asn->TechEmail;

  my @contact = $w->contact('DM2339-ARIN');

  my @contact_records = $w->domain('eli.net');

  my @org = $w->organization('ELIX');

  my @customers = $w->customer('ELIX');

=head1 DESCRIPTION

This module provides a Perl interface to the ARIN Whois server.  The module takes care of connecting to an ARIN whois server, sending your whois requests, and parsing the whois output.  The whois records are returned as lists of Net::Whois::ARIN::* instances.

=cut

use strict;

use vars qw/ $VERSION /;
$VERSION = '0.07';

use Carp;
use IO::Socket;
use Net::Whois::ARIN::AS;
use Net::Whois::ARIN::Contact;
use Net::Whois::ARIN::Customer;
use Net::Whois::ARIN::Network;
use Net::Whois::ARIN::Organization;

=pod

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

=cut

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
        croak "can't connect to ${host}\[$port\]: $error";
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

=pod

=item B<network> - request a network record

  my @records = $o->network('207.173.112.0');

This method requires a single argument.  The argument indicates the network to use in the whois lookup.  The method returns a list of Net::Whois::ARIN::Network records that matched your search criteria.

=cut

sub network {
    my ($self, $query) = @_;
    my @output  = $self->query("n + $query");
    my @contacts;
    my @records;
    my %attributes;
    my $record_count = 0;
    my $found_contact_info = 0;
    foreach (@output) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;
  
        if ($key eq 'OrgName' || $key eq 'CustName') { 
            $record_count++;
            unless ($record_count > 1) {
                $attributes{$key} = $value;
                next;
            }
            my $net = Net::Whois::ARIN::Network->new( %attributes );
            $net->contacts( @contacts );
            push @records, $net;
            $found_contact_info = 0;
            @contacts = ();
            %attributes = ();
        }
  
        if ($key =~ /^(Tech|NOC|OrgAbuse|OrgTech|Abuse)(\w+)$/ ) {
            $found_contact_info ++;
            if ($2 eq 'Handle') {
                push @contacts, $self->contact( $value );
                $contacts[-1]->Type( $1 );
            }
        }
        elsif( !$found_contact_info ) {
            $attributes{$key} = $value;
        }
    }

    my $net = Net::Whois::ARIN::Network->new( %attributes );
    $net->contacts( @contacts );
    push @records, $net;

    return @records;
}

=pod

=item B<asn> - request an ASN record

  my @record = $o->asn(5650);

This method requires a single argument.  The argument indicates the autonomous system number to us in the whois lookup.  The method returns a list of Net::Whois::ARIN::AS objects.  

=cut

sub asn {
    my ($self, $query) = @_;
    my @output  = $self->query("a + $query");
    my(%attributes, @contacts);

    foreach ( @output ) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;
        if ($key eq 'Address') {
            $attributes{Address} .= "$value\n";
        }
        elsif( $key =~ /^(Tech|NOC|OrgAbuse|OrgTech|Abuse)(\w+)$/ ) {
            if ($2 eq 'Handle') {
                push @contacts, $self->contact( $value );
                $contacts[-1]->Type( $1 );
            }            
        }
        else {
            $attributes{$key} = $value;
        }
    }

    chomp( $attributes{Address} )
        if exists $attributes{Address};

    my $as = Net::Whois::ARIN::AS->new( %attributes );
    $as->contacts( @contacts );
    return $as;
}

=pod

=item B<organization> - request an organization record

  my @record = $w->org('ELIX');

=cut

sub organization {
    my ($self, $query) = @_;
    my @output  = $self->query("o + $query");

    my @records;
    my(%attributes, @contacts);
    my $record_count = 0;
    my $found_contact_info = 0;

    foreach ( @output ) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;

        if ($key eq 'OrgName') {
            $record_count++;
            unless ($record_count > 1) {
                $attributes{$key} = $value;
                next;
            }
            my $org = Net::Whois::ARIN::Organization->new( %attributes );
            $org->contacts( @contacts );
            push @records, $org;
            $found_contact_info = 0;
            @contacts = ();
            %attributes = ();
        }
        if ($key eq 'Address') {
            $attributes{Address} .= "$value\n";
        }
        elsif( $key =~ /^(Tech|NOC|OrgAbuse|OrgTech|Abuse)(\w+)$/ ) {
            $found_contact_info ++;
            if ($2 eq 'Handle') {
                push @contacts, $self->contact( $value );
                $contacts[-1]->Type( $1 );
            }
        }
        elsif( !$found_contact_info ) {
            $attributes{$key} = $value;
        }
    }

    chomp( $attributes{Address} )
        if exists $attributes{Address};

    my $org = Net::Whois::ARIN::Organization->new( %attributes );
    $org->contacts( @contacts );
    push @records, $org;
    return @records;
}

=pod

=item B<customer> - request a customer record

  my @records = $w->customer('ELIX');

=cut

sub customer {
    my ($self, $query) = @_;
    my @output  = $self->query("c + $query");

    my @records;
    my(%attributes, @contacts);
    my $record_count = 0;
    my $found_contact_info = 0;

    foreach ( @output ) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;

        if ($key eq 'CustName') {
            $record_count++;
            unless ($record_count > 1) {
                $attributes{$key} = $value;
                next;
            }
            my $cust = Net::Whois::ARIN::Customer->new( %attributes );
            $cust->contacts( @contacts );
            push @records, $cust;
            $found_contact_info = 0;
            @contacts = ();
            %attributes = ();
        }
        if ($key eq 'Address') {
            $attributes{Address} .= "$value\n";
        }
        elsif( $key =~ /^(Tech|NOC|OrgAbuse|OrgTech|Abuse)(\w+)$/ ) {
            $found_contact_info ++;
            if ($2 eq 'Handle') {
                push @contacts, $self->contact( $value );
                $contacts[-1]->Type( $1 );
            }
        }
        elsif( !$found_contact_info ) {
            $attributes{$key} = $value;
        }
    }

    chomp( $attributes{Address} )
        if exists $attributes{Address};

    my $cust = Net::Whois::ARIN::Customer->new( %attributes );
    $cust->contacts( @contacts );
    push @records, $cust;
    return @records;
}

=pod

=item B<contact> - request a point-of-contact record

  my @record = $w->contact('DM2339-ARIN');

=cut

sub contact {
    my ($self, $query) = @_;
    my @output  = $self->query("p + $query");
    my @records;
    my $n = -1;
    foreach ( @output ) {
        next unless $_ =~ /^(\S+):\s+(.*)$/;
        my ($key, $value) = ($1, $2);
        $value =~ s/\s*$//;
        $records[++$n] = {} if /^Name:/;
        if ($key eq 'Address') {
            $records[$n]->{Address} .= "$value\n";
        }
        else {
            $records[$n]->{$key} = $value;
        }
    }

    my @contacts;
    foreach ( @records ) {
        my %attributes = %$_;
        chomp($attributes{Address})
            if exists $attributes{Address};
        push @contacts, Net::Whois::ARIN::Contact->new( %attributes );
    }

    return @contacts;
}

=pod

=item B<domain> - request all records from a given domain

  @output = $w->domain('eli.net');

=back

=cut

sub domain {
    my ($self, $query) = @_;
    $query = "\@$query" if $query !~ /^\@/;
    $query = "+ $query";
    my @output = $self->query($query);
    my @contacts;
    my %attr;
    foreach (@output) {
         if(/^(\S+):\s+(.*)$/) {
             $attr{$1} = $2;
         }
         if(/^Email:\s+.*$/) {
             push @contacts, Net::Whois::ARIN::Contact->new( %attr );
             %attr = ();
         }
    }
    return @contacts;
}

=pod

=head1 SEE ALSO

Net::Whois::ARIN::AS
Net::Whois::ARIN::Network
Net::Whois::ARIN::Contact
Net::Whois::ARIN::Organization
Net::Whois::ARIN::Customer

=head1 AUTHOR

Todd Caine  <todd at pobox.com>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2002, 2003, 2004 Todd Caine.  All rights reserved. This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut


1;
__END__
