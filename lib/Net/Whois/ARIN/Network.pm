package Net::Whois::ARIN::Network;
# $Id: Network.pm,v 1.7 2004/05/14 22:43:28 tcaine Exp $

=pod

=head1 NAME

Net::Whois::ARIN::Network - ARIN whois Network record class

=head1 SYNOPSIS

  use Net::Whois::ARIN::Network;

  my $net = Net::Whois::ARIN::Network->new(
               OrgName    => 'Electric Lightwave Inc',
               OrgID      => 'ELIX',
               Address    => '4400 NE 77th Ave',
               City       => 'Vancouver',
               StateProv  => 'WA',
               PostalCode => '98662',
               Country    => 'US',
               RegDate    => '1995-07-25',
               Updated    => '2001-05-17',
               NetRange   => '207.173.0.0 - 207.173.255.255',
               CIDR       => '207.173.0.0/16',
               NetName    => 'ELI-NETBLK5',
               NetHandle  => 'NET-207-173-0-0-1',
               Parent     => 'NET-207-0-0-0-0',
               NetType    => 'Direct Allocation',
               NameServer => 'NS.ELI.NET',
               Comment    => 'ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE',
           );

  printf "%s was given a %s of %s by ARIN.\n", 
         $net->OrgName, 
         lc $net->NetType, 
         $net->CIDR;

=head1 DESCRIPTION

The Net::Whois::ARIN::Network module is simple class which is used to store the attributes of an Network record in ARIN's Whois server.  Each attribute of the Network record has an accessor/mutator of the same name.

=cut

use strict;
use vars qw{ $VERSION };
$VERSION = '0.01';

=pod

=head1 METHODS

=over 4

=item B<new> - create a Net::Whois::ARIN::Network object

=cut

sub new {
    my $class = shift;
    return bless { _contacts => [], @_ }, $class;
}

=pod

=item B<contacts> - get/set Net::Whois::ARIN::Contact records

This method accepts a list of Net::Whois::ARIN::Contact instances and associates these objects with the Network record.  If no arguments are specified, the method returns a list of Net::Whois::ARIN::Contact objects.

=back

=cut

sub contacts {
    my $self = shift;
    $self->{_contacts} = [ @_ ] if @_;
    return @{ $self->{_contacts} };
}

=pod

=item B<dump> - return the current whois record

  print $o->dump;

=cut

sub dump {
    my $self = shift;
    my $record = sprintf "\nOrgName:    %s\n", $self->OrgName;
    $record .= sprintf "OrgID:      %s\n",$self->OrgID;
    $record .= sprintf("Address:    %s\n", $_) for @{ $self->Address };
    $record .= sprintf "City:       %s\n",$self->City;
    $record .= sprintf "StateProv:  %s\n",$self->StateProv;
    $record .= sprintf "PostalCode: %s\n",$self->PostalCode;
    $record .= sprintf "Country:    %s\n",$self->Country;
    $record .= sprintf "RegDate:    %s\n",$self->RegDate;
    $record .= sprintf "Updated:    %s\n\n",$self->Updated;

    $record .= sprintf "NetRange:   %s\n",$self->NetRange;
    $record .= sprintf "CIDR:       %s\n",$self->CIDR;
    $record .= sprintf "NetName:    %s\n",$self->NetName;
    $record .= sprintf "NetHandle:  %s\n",$self->NetHandle;
    $record .= sprintf "Parent:     %s\n",$self->Parent;
    $record .= sprintf "NetType:    %s\n",$self->NetType;
    $record .= sprintf("NameServer: %s\n", $_) for @{ $self->NameServer };
    $record .= sprintf "Comment:    %s\n",$self->Comment;
    $record .= sprintf "RegDate:    %s\n",$self->RegDate;
    $record .= sprintf "Updated:    %s\n",$self->Updated;

    foreach my $contact ( $self->contacts ) {
        $record .= sprintf "%sHandle: %s\n", $contact->Type, $contact->Handle;
        $record .= sprintf "%sName: %s\n", $contact->Type, $contact->Name;
        $record .= sprintf "%sPhone: %s\n", $contact->Type, $contact->Phone;
        $record .= sprintf "%sEmail: %s\n", $contact->Type, $contact->Email;
    }

    return $record;
}

=pod

=head1 ATTRIBUTES

These methods are the accessors/mutators for the fields found in the Whois record.

=over 4

=item B<OrgName> - get/set the organization name

=item B<OrgID> - get/set the organization id

=item B<Address> - get/set the address

=item B<City> - get/set the city

=item B<StateProv> - get/set the state or province

=item B<PostalCode> - get/set the postal code

=item B<Country> - get/set the country

=item B<RegDate> - get/set the registration date

=item B<Updated> - get/set the last updated date

=item B<NetRange> - get/set the network range

=item B<CIDR> - get/set the CIDR netblock

=item B<NetName> - get/set the network name

=item B<NetHandle> - get/set the network handle

=item B<Parent> - get/set the parent network handle

=item B<NetType> - get/set the network type

=item B<NameServer> - get/set the name servers

=item B<Comment> - get/set the public comment

=back

=cut

use Class::MethodMaker get_set => [qw(
    OrgName OrgID Address City StateProv PostalCode Country
    RegDate Updated NetRange CIDR NetName NetHandle
    Parent NetType NameServer Comment
)];

=pod

=head1 AUTHOR

Todd Caine   <todd at pobox.com>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2004 Todd Caine.  All rights reserved. This program is free software; you can redistribute it and/or modify it u
nder the same terms as Perl itself.

=cut

1;
__END__
