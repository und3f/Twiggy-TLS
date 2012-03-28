use inc::Module::Install;

name 'Twiggy-TLS';
all_from 'lib/Twiggy/TLS.pm';

requires 'Twiggy' => '0.1010';
requires 'Plack'  => '0.99';
requires 'IO::Socket::SSL' => '1.62';

test_requires 'Test::More' => '0.88';
test_requires 'Test::TCP';
test_requires 'LWP::UserAgent';
test_requires 'LWP::Protocol::https';
test_requires 'FindBin';

WriteAll;
