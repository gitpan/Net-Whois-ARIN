package Net::Whois::ARIN::Contact;
# $Id: Contact.pm,v 1.7 2004/05/28 02:57:20 tcaine Exp $

=pod

=head1 NAME

Net::Whois::ARIN::Contact - ARIN whois Contact record class

=head1 SYNOPSIS

  use Net::Whois::ARIN::Contact;

  my $poc = Net::Whois::ARIN::Contact->new(
               Name       => 'Caine, Todd',
               Handle     => 'TCA53-ARIN',
               Company    => 'Electric Lightwave',
               Address    => '4400 NE 77th Ave',
               City       => 'Vancouver',
               StateProv  => 'WA',
               PostalCode => '98662',
               Country    => 'US',
               Comment    => '',
               RegDate    => '1995-07-25',
               Updated    => '2001-05-17',
               Phone      => '503-555-1212',
               Email      => 'nobody@nobody.net',
           );

  printf "The ARIN contact handle for %s is %s.\n",
         $poc->Name,
         $poc->Handle;

=head1 DESCRIPTION

The Net::Whois::ARIN::Contact module is simple class which is used to store the attributes of a point-of-contact record in ARIN's Whois server.  Each attribute of the contact record has an accessor/mutator of the same name.

=cut

use strict;
use vars qw{ $VERSION };
$VERSION = '0.08';

=pod

=head1 METHODS

=over 4

=item B<new> - create a Net::Whois::ARIN::Contact object

=cut

sub new {
    my $class = shift;
    return bless { @_ }, $class;
}

=pod

=item B<dump> - return the current whois record

  print $o->dump;

=cut

sub dump {
    my $self = shift;
    my $record = sprintf "\nName:       %s\n",$self->Name;
    $record .= sprintf "Handle:     %s\n",$self->Handle;
    $record .= sprintf "Company:    %s\n",$self->Company;
    $record .= sprintf("Address:    %s\n", $_) for @{ $self->Address };
    $record .= sprintf "City:       %s\n",$self->City;
    $record .= sprintf "StateProv:  %s\n",$self->StateProv;
    $record .= sprintf "PostalCode: %s\n",$self->PostalCode;
    $record .= sprintf "Country:    %s\n",$self->Country;
    $record .= sprintf "Comment:    %s\n",$self->Comment;
    $record .= sprintf "RegDate:    %s\n",$self->RegDate;
    $record .= sprintf "Updated:    %s\n",$self->Updated;
    $record .= sprintf "Phone:      %s\n",$self->Phone;
    $record .= sprintf "Email:      %s\n",$self->Email;
    return $record;
}

=pod

=head1 ATTRIBUTES

These methods are the accessors/mutators for the fields found in the Whois record.

=item B<Type> - get/set the contact type

=item B<Name> - get/set the contact name

=item B<Handle> - get/set the contact handle

=item B<Company> - get/set the company

=item B<Address> - get/set the address

=item B<City> - get/set the city

=item B<StateProv> - get/set the state or province

=item B<PostalCode> - get/set the postal code

=item B<Country> - get/set the country

=item B<RegDate> - get/set the registration date

=item B<Updated> - get/set the last updated date

=item B<Phone> - get/set the contact phone number

=item B<Email> - get/set the contact email address

=item B<Comment> - get/set the public comment

=back

=cut

use Class::MethodMaker get_set => [qw(
    Type Name Handle Company 
    Address City StateProv PostalCode Country 
    Comment RegDate Updated Phone Email
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
