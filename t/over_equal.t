
#use diagnostics;
use NetAddr::IP::Lite;

$| = 1;

print "1..8\n";

my $test = 1;
sub ok() {
  print 'ok ',$test++,"\n";
}

my $four	= new NetAddr::IP::Lite('0.0.0.4');		# same as 0.0.0.4/32
my $four120	= new NetAddr::IP::Lite('::4/120');	# same as 0.0.0.4/24

my $t432	= '0.0.0.4/32';
my $t4120	= '0:0:0:0:0:0:0:4/120';

## test '""' overload
my $txt = sprintf ("%s",$four120);

print "got: $txt, exp: $t4120\nnot "
	unless $txt eq $t4120;
&ok;

## test '""' again
$txt = sprintf ("%s",$four);

print "got: $txt, exp: $t432\nnot "
	unless $txt eq $t432;
&ok;

## test 'eq' to scalar
print 'failed ',$four," eq $t432\nnot "
	unless $four eq $t432;
&ok;

## test scalar 'eq' to
print "failed $t432 eq ",$four,"\nnot "
	unless $t432 eq $four;
&ok;

## test 'eq' to self
print 'failed ',$four,' eq ', $four,"\nnot "
	unless $four eq $four;
&ok;

## test 'eq' cidr !=
print 'failed ',$four,' should not eq ',$four120,"\nnot "
	if $four eq $four120;
&ok;

## test '==' not for scalars
print "failed scalar $t432 should not == ",$four,"\nnot "
	if $t432 == $four;
&ok;

## test '== not for scalar, reversed args
print 'failed scalar ',$four," should not == $t432\nnot "
	if $four == $t432;
&ok;

