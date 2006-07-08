use Test::More tests => 12;
use NetAddr::IP::Lite;

my @good = (qw(default any broadcast loopback));
my @bad = map { ("$_.neveranydomainlikethis",
		 "nohostlikethis.$_") } @good;

ok(defined NetAddr::IP::Lite->new($_), "defined ->new($_)")
    for @good;

my $bad = scalar @bad;

diag <<EOF;

\tThe following $bad tests involve resolving (hopefully) 
\tnon-existant names. This may take a while.
EOF

ok(! defined NetAddr::IP::Lite->new($_), "not defined ->new($_)")
    for @bad;

