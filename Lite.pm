#!/usr/bin/perl

package NetAddr::IP::Lite;

=head1 NAME

NetAddr::IP::Lite - Manages IPv4 and IPv6 addresses and subnets

=head1 SYNOPSIS

  use NetAddr::IP::Lite;

  my $ip = new NetAddr::IP::Lite '127.0.0.1';

  print "The address is ", $ip->addr, " with mask ", $ip->mask, "\n" ;

  if ($ip->within(new NetAddr::IP::Lite "127.0.0.0", "255.0.0.0")) {
      print "Is a loopback address\n";
  }

				# This prints 127.0.0.1/32
  print "You can also say $ip...\n";

=head1 INSTALLATION

Un-tar the distribution in an appropriate directory and type:

	perl Makefile.PL
	make
	make test
	make install

B<NetAddr::IP::Lite> depends on B<NetAddr::IP::Util> which installs by default with its primary functions compiled
using Perl's XS extensions to build a 'C' library. If you do not have a 'C'
complier available or would like the slower Pure Perl version for some other
reason, then type:

	perl Makefile.PL -noxs
	make
	make test
	make install

=head1 DESCRIPTION

This module provides an object-oriented abstraction on top of IP
addresses or IP subnets, that allows for easy manipulations. Most of the
operations of NetAddr::IP are supported. This module will work older
versions of Perl and does B<not> use Math::BigInt.

The internal representation of all IP objects is in 128 bit IPv6 notation.
IPv4 and IPv6 objects may be freely mixed.

The supported operations are described below:

=head2 Overloaded Operators

=cut

use Carp;
use strict;
use warnings;
use NetAddr::IP::Util qw(
	inet_any2n
	addconst
	sub128
	ipv6to4
	notcontiguous
	isIPv4
	shiftleft
	inet_n2dx
	hasbits
	bin2bcd
);
use vars qw($Class $VERSION);

$VERSION = do { my @r = (q$Revision: 0.02 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

my $_zero = pack('L4',0,0,0,0);
my $_ones = ~$_zero;
my $_v4mask = pack('L4',0xffffffff,0xffffffff,0xffffffff,0);
my $_v4net = ~ $_v4mask;

sub Zero() {
  return $_zero;
}
sub Ones() {
  return $_ones;
}
sub V4mask() {
  return $_v4mask;
}
sub V4net() {
  return $_v4net;
}

				#############################################
				# These are the overload methods, placed here
				# for convenience.
				#############################################

use overload

    '+'		=> \&plus,

    '-'		=> \&minus,

    '++'	=> \&plusplus,

    '--'	=> \&minusminus,

    "="		=> sub {
	return _new($_[0],$_[0]->{addr}, $_[0]->{mask});
    },

    '""'	=> sub { $_[0]->cidr(); },

    'eq'	=> sub { 
	my $a = ref $_[0] eq $Class ? $_[0]->cidr : $_[0];
	my $b = ref $_[1] eq $Class ? $_[1]->cidr : $_[1];
	$a eq $b;
    },

    '=='	=> sub { 
	return 0 unless ref $_[0] eq $Class;
	return 0 unless ref $_[1] eq $Class;
	$_[0]->cidr eq $_[1]->cidr;
    },

    '>'		=> sub {	# reverse operands, carry = 0
	return ! scalar sub128($_[1]->{addr},$_[0]->{addr});
    },

    '<'		=> sub {	# carry = 0
	return ! scalar sub128($_[0]->{addr},$_[1]->{addr});
    },

    '>='	=> sub {	# carry = 1
	return scalar sub128($_[0]->{addr},$_[1]->{addr});
    },

    '<='	=> sub {	# reverse operands, carry = 1
	return scalar sub128($_[1]->{addr},$_[0]->{addr});
    },

    '<=>'		=> sub {
	my($carry,$rv) = sub128($_[0]->{addr},$_[1]->{addr});
	return -1 unless $carry;
	return (hasbits($rv)) ? 1 : 0;
    },

    'cmp'		=> sub {
	my($carry,$rv) = sub128($_[0]->{addr},$_[1]->{addr});
	return -1 unless $carry;
	return (hasbits($rv)) ? 1 : 0;
    };

=pod

=over

=item B<Assignment (C<=>)>

Has been optimized to copy one NetAddr::IP::Lite object to another very quickly.

=item B<Stringification>

An object can be used just as a string. For instance, the following code

	my $ip = new NetAddr::IP::Lite '192.168.1.123';
        print "$ip\n";

Will print the string 192.168.1.123/32.

=item B<Equality>

You can test for equality with either C<eq> or C<==>. C<eq> allows the
comparison with arbitrary strings as well as NetAddr::IP::Lite objects. The
following example:

    if (NetAddr::IP::Lite->new('127.0.0.1','255.0.0.0') eq '127.0.0.1/8') 
       { print "Yes\n"; }

Will print out "Yes".

Comparison with C<==> requires both operands to be NetAddr::IP::Lite objects.

In both cases, a true value is returned if the CIDR representation of
the operands is equal.

=item B<Comparison via E<gt>, E<lt>, E<gt>=, E<lt>=, E<lt>=E<gt> and C<cmp>>

Internally, all network objects are represented in 128 bit format.
The numeric representation of the network is compared through the 
corresponding operation. The netmask is
ignored for these comparisons, as there is no standard criteria to say
wether 10/8 is larger than 10/10 or not.

=item B<Addition of a constant>

Adding a constant to a NetAddr::IP::Lite object changes its address part to
point to the one so many hosts above the start address. For instance,
this code:

    print NetAddr::IP::Lite->new('127.0.0.1') + 5;

will output 127.0.0.6/8. The address will wrap around at the broadcast
back to the network address. This code:

    print NetAddr::IP::Lite->new('10.0.0.1/24') + 255;

outputs 10.0.0.0/24.

=cut

sub plus {
    my $ip	= shift;
    my $const	= shift;

    return $ip unless $const;

    my $a = $ip->{addr};
    my $m = $ip->{mask};
    
    my $lo = $a & ~$m;
    my $hi = $a & $m;

    my $new = ((addconst($lo,$const))[1] & ~$m) | $hi;

    return _new($ip,$new,$m);
}

=item B<Substraction of a constant>

The complement of the addition of a constant.

=cut

sub minus {
    my $ip	= shift;
    my $const	= shift;

    return plus($ip, -$const);
}

				# Auto-increment an object

=item B<Auto-increment>

Auto-incrementing a NetAddr::IP::Lite object causes the address part to be
adjusted to the next host address within the subnet. It will wrap at
the broadcast address and start again from the network address.

=cut

sub plusplus {
    my $ip	= shift;

    my $a = $ip->{addr};
    my $m = $ip->{mask};

    my $lo = $a & ~ $m;
    my $hi = $a & $m; 

    $ip->{addr} = ((addconst($lo,1))[1] & ~ $m) | $hi;
    return $ip;
}

=item B<Auto-decrement>

Auto-decrementing a NetAddr::IP::Lite object performs exactly the opposite
of auto-incrementing it, as you would expect.

=cut

sub minusminus {
    my $ip	= shift;

    my $a = $ip->{addr};
    my $m = $ip->{mask};

    my $lo = $a & ~$m;
    my $hi = $a & $m; 

    $ip->{addr} = ((addconst($lo,-1))[1] & ~$m) | $hi;
    return $ip;
}

				#############################################
				# End of the overload methods.
				#############################################

# Preloaded methods go here.

				# This is a variant to ->new() that
				# creates and blesses a new object
				# without the fancy parsing of
				# IP formats and shorthands.

# return a blessed IP object without parsing
# input:	prototype, naddr, nmask
# returns:	blessed IP object
#
sub _new ($$$) {
  my $proto = shift;
  my $class = ref($proto) || die "reference required";
  my $self = {
	addr	=> $_[0],
	mask	=> $_[1],
  };
  return bless $self, $class;
}

=pod

=back

=head2 Methods

=over

=item C<-E<gt>new([$addr, [ $mask]])>

This method creates a new address with the supplied address in
C<$addr> and an optional netmask C<$mask>, which can be omitted to get
a /32 or /128 netmask for IPv4 / IPv6 addresses respectively

C<$addr> can be any of the following:

  n.n.n.n
  n.n.n.n/mm		32 bit cidr notation
  n.n.n.n/m.m.m.m

Any RFC1884 notation

  ::n.n.n.n
  ::n.n.n.n/mmm		128 bit cidr notation
  ::n.n.n.n/::m.m.m.m
  ::x:x
  ::x:x/mmm
  x:x:x:x:x:x:x:x
  x:x:x:x:x:x:x:x/mmm
  x:x:x:x:x:x:x:x/m:m:m:m:m:m:m:m any RFC1884 notation

If called with no arguments, 'default' is assumed.

=cut

sub new {
  my($proto,$ip,$mask) = @_;
  return undef unless $ip;
# save Class for inheritance
  $Class = ref($proto) || $proto;
  my($naddr,$nmask);
  if ($ip =~ m|^([0-9a-fA-F:.]+)/(\d{1,3})$|) {
    return undef unless ($naddr = inet_any2n($1));
    $mask = $2;
    $mask = $ip =~ /:/ ? 128 - $mask : 32 - $mask;
    return undef if $mask < 0 || $mask > 128;
    $nmask = shiftleft(Ones,$mask);
  } elsif ($ip =~ m|^([0-9a-fA-F:.]+)/([0-9a-fA-F:.]+)$|) {

    return undef unless ($naddr = inet_any2n($1));
    return undef unless ($nmask = inet_any2n($2));
    $nmask |= V4mask if isIPv4($naddr);
  } else {
    return undef unless ($naddr = inet_any2n($ip));
    if ($mask) {
      return undef unless ($nmask = inet_any2n($mask));
      $nmask |= V4mask if isIPv4($naddr);
    } else {
      $nmask = Ones;
    }
  }
  return undef if notcontiguous($nmask);
  my $self = {
	addr	=> $naddr,
	mask	=> $nmask,
  };
  return bless $self, $Class;
}

=item C<-E<gt>broadcast()>

Returns a new object refering to the broadcast address of a given
subnet. The broadcast address has all ones in all the bit positions
where the netmask has zero bits. This is normally used to address all
the hosts in a given subnet.

=cut

sub broadcast ($) {
    my $self	= shift;
    return _new($self,$self->{addr} | ~ $self->{mask},$self->{mask});
}

=item C<-E<gt>network()>

Returns a new object refering to the network address of a given
subnet. A network address has all zero bits where the bits of the
netmask are zero. Normally this is used to refer to a subnet.

=cut

sub network ($) {
  my $self = shift;
  return _new($self,$self->{addr} & $self->{mask},$self->{mask});
}

=item C<-E<gt>addr()>

Returns a scalar with the address part of the object as an IPv4 or IPv6 text
string as appropriate. This is useful for printing or for passing the address
part of the NetAddr::IP::Lite object to other components that expect an IP
address.

=cut

sub addr ($) {
  return inet_n2dx($_[0]->{addr});
}

=item C<-E<gt>mask()>

Returns a scalar with the mask as an IPv4 or IPv6 text string as
appropriate.

=cut

sub mask ($) {
  my $self	= shift;
  my $mask = isIPv4($self->{addr})
	? $self->{mask} & V4net
	: $self->{mask};
  return inet_n2dx($mask);
}

=item C<-E<gt>masklen()>

Returns a scalar the number of one bits in the mask.

=cut

sub masklen ($) {
  my $self = shift;
  my $len = (notcontiguous($self->{mask}))[1];
  return isIPv4($self->{addr})
	? $len -96
	: $len;
}

=item C<-E<gt>bits()>

Returns the wide of the address in bits. Normally 32 for v4 and 128 for v6.

=cut

sub bits {
  return isIPv4($_[0]->{addr})
	? 32
	: 128;
}

=item C<-E<gt>version()>

Returns the version of the address or subnet. Currently this can be
either 4 or 6.

=cut

sub version {
  return isIPv4($_[0]->{addr})
	? 4
	: 6;
}

=item C<-E<gt>cidr()>

Returns a scalar with the address and mask in CIDR notation. A
NetAddr::IP::Lite object I<stringifies> to the result of this function.

=cut

sub cidr ($) {
    my $self	= shift;
    return $self->addr . '/' . $self->masklen;
}

=item C<-E<gt>aton()>

Returns the address part of the NetAddr::IP::Lite object in the same format
as the C<inet_aton()> or C<ipv6_aton> function respectively.

=cut

sub aton {
  my $self = shift;
  return isIPv4($self->{addr})
	? ipv6to4($self->{addr})
	: $self->{addr};
}

=item C<-E<gt>range()>

Returns a scalar with the base address and the broadcast address
separated by a dash and spaces. This is called range notation.

=cut

sub range ($) {
    my $self = shift;
    return $self->network->addr . ' - ' . $self->broadcast->addr;
}

=item C<-E<gt>numeric()>

When called in a scalar context, will return a numeric representation
of the address part of the IP address. When called in an array
contest, it returns a list of two elements. The first element is as
described, the second element is the numeric representation of the
netmask.

This method is essential for serializing the representation of a
subnet.

=cut

sub numeric ($) {
  my $self = shift;
  my $n = $self->aton;
  if (wantarray) {
    if (isIPv4($self->{addr})) {
      return (	sprintf("%u",unpack('N',ipv6to4($self->{addr}))),
		sprintf("%u",unpack('N',ipv6to4($self->{mask}))));
    }
    else {
      return (	bin2bcd($self->{addr}),
		bin2bcd($self->{mask}));
    }
  }
  return isIPv4($self->{addr})
    ? sprintf("%u",unpack('N',ipv6to4($self->{addr})))
    : bin2bcd($self->{addr});
}

=item C<$me-E<gt>contains($other)>

Returns true when C<$me> completely contains C<$other>. False is
returned otherwise and C<undef> is returned if C<$me> and C<$other>
are not both C<NetAddr::IP::Lite> objects.

=cut

sub contains ($$) {
  return within(@_[1,0]);
}

=item C<$me-E<gt>within($other)>

The complement of C<-E<gt>contains()>. Returns true when C<$me> is
completely contained within C<$other>, undef if C<$me> and C<$other>
are not both C<NetAddr::IP::Lite> objects.

=cut

sub within ($$) {
  return undef unless ref($_[0]) eq $Class && ref($_[1]) eq $Class;
  my $net = $_[1]->{addr} & $_[1]->{mask};
  my $brd = $_[1]->{addr} | ~ $_[1]->{mask};
  return (sub128($_[0]->{addr},$net) && sub128($brd,$_[0]->{addr}))
	? 1 : 0;
}

=item C<-E<gt>first()>

Returns a new object representing the first useable IP address within
the subnet (ie, the first host address).

=cut

sub first ($) {
    my $self	= shift;
    return $self->network + 1;
}

=item C<-E<gt>last()>

Returns a new object representing the last useable IP address within
the subnet (ie, one less than the broadcast address).

=cut

sub last ($) {
    my $self	= shift;
    return $self->broadcast - 1;
}

=item C<-E<gt>nth($index)>

Returns a new object representing the I<n>-th useable IP address within
the subnet (ie, the I<n>-th host address).  If no address is available
(for example, when the network is too small for C<$index> hosts),
C<undef> is returned.

=cut

sub nth ($$) {
    my $self    = shift;
    my $count   = shift;

    return undef if ($count < 1 or $count > $self->num ());
    return $self->network + $count;
}

=item C<-E<gt>num()>

Returns the number of useable IP addresses within the
subnet, not counting the broadcast address.

=cut

sub num ($) {
    my $self	= shift;
    my $n = 128 - (notcontiguous($self->{mask}))[1];
    my $addrs = (2 ** $n) -1;
    return ($addrs > 2)
	? $addrs
	: 1;
}

1;

=pod

=back

=head2 EXPORT

None by default.

=head1 AUTHOR

Luis E. Muñoz <luismunoz@cpan.org>
Michael Robinton <michael@bizsystems.com>

=head1 WARRANTY

This software comes with the  same warranty as perl itself (ie, none),
so by using it you accept any and all the liability.

=head1 LICENSE

This software is (c) Luis E. Muñoz, 1999 - 2005, and (c) Michael Robinton, 2006.
It can be used under the terms of the perl artistic license provided that 
proper credit for the work of the author is preserved in the form of this 
copyright notice and license for this module.

=head1 SEE ALSO

perl(1), NetAddr::IP(3), NetAddr::IP::Util(3)

=cut

1;
