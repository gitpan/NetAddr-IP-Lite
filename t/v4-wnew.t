use Test::More tests => 12;
use NetAddr::IP::Lite;

my @good = (qw(default any broadcast loopback));
my @bad = map { ("$_.neveranydomainlikethis",
		 "nohostlikethis.$_") } @good;

ok(defined NetAddr::IP::Lite->new($_), "defined ->new($_)")
    for @good;

ok(! defined NetAddr::IP::Lite->new($_), "not defined ->new($_)")
    for @bad;

