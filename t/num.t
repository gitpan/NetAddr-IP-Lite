
#use diagnostics;
use NetAddr::IP::Lite;

$| = 1;

print "1..2\n";

my $test = 1;
sub ok() {
  print 'ok ',$test++,"\n";
}

my $ip4 = NetAddr::IP::Lite->new('1.2.3.11/29');
my $ip6 = NetAddr::IP::Lite->new('FF::8B/125');

my $exp = 7;

print "got: $_, exp: $exp\nnot "
	unless $ip4->num == 7;
&ok;

print "got: $_, exp: $exp\nnot "
	unless $ip6->num == 7;
&ok;
