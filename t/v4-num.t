use NetAddr::IP::Lite;

my $nets = {
    '10.0.0.16'		=> [ 24, 255 ],
    '10.128.0.1'	=> [ 8, 2 ** 24 - 1 ],
    '10.0.0.5'		=> [ 30, 3 ],
};

$| = 1;
print "1..", (scalar keys %$nets), "\n";

my $count = 1;

for my $a (keys %$nets) {
    my $ip = new NetAddr::IP::Lite $a, $nets->{$a}->[0];

    print '', (($ip->num != $nets->{$a}->[1] ? 
	    'not ' : ''), 
	   "ok ", $count++, "\n");
}


