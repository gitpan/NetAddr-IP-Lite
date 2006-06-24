use Test::More tests => 18;
use Socket;

my @addr = (
	[ 'localhost', '127.0.0.1' ],
	[ 'broadcast', '255.255.255.255' ],
	[ '254.254.0.1', '254.254.0.1' ],
	[ 'default', '0.0.0.0' ],
	[ '10.0.0.1', '10.0.0.1' ],

);

# Verify that Accept_Binary_IP works...

SKIP:
{
    skip "Failed to load NetAddr::IP::Lite", 17
	unless use_ok('NetAddr::IP::Lite');

    ok(! defined NetAddr::IP::Lite->new("\1\1\1\1"), 
       "binary unrecognized by default...");

    # This mimicks the actual use with :aton
    NetAddr::IP::Lite::import(':aton');

    ok(defined NetAddr::IP::Lite->new("\1\1\1\1"), 
       "...but can be recognized");

    is(NetAddr::IP::Lite->new($_->[0])->aton, inet_aton($_->[1]), "->aton($_->[0])")
	for @addr;

    ok(defined NetAddr::IP::Lite->new(inet_aton($_->[1])), "->new aton($_->[1])")
	for @addr;

    is(NetAddr::IP::Lite->new(inet_aton($_->[1]))->addr, $_->[1], 
       "->new aton($_->[1])")
	for @addr;
}
