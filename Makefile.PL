use inc::Module::Install;

name 'Twiggy-Server-TLS';
all_from 'lib/Twiggy/TLS.pm';

requires 'Twiggy';
requires 'IO::Socket::SSL' => '1.56';

test_requires 'Test::More' => '0.88';
test_requires 'Test::TCP';
test_requires 'LWP::UserAgent';
test_requires 'LWP::Protocol::https';

WriteAll;
