#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::TCP;
use Plack::Loader;
use LWP::UserAgent;
use FindBin '$Bin';

my $ca_cert    = "$Bin/ca.pem";
my $server_pem = "$Bin/server.pem";

subtest 'tls connection' => sub {
    my $success;

    test_tcp(
        client => sub {
            my $port = shift;

            alarm 2;
            local $SIG{ALRM} = sub {die};

            my $ua =
              LWP::UserAgent->new(
                ssl_opts => {verify_hostname => 1, SSL_ca_file => $ca_cert});
            my $res = $ua->get("https://localhost:$port");
            $success = $res->is_success or die $res->status_line;
        },
        server => sub {
            my $port   = shift;
            my $server = Plack::Loader->load(
                'Twiggy::TLS',
                port     => $port,
                host     => '127.0.0.1',
                ssl_key  => $server_pem,
                ssl_cert => $server_pem,
            );

            $server->run(
                sub {
                    return [200, ['Content-Type' => 'text/plain'], ['hello']];
                }
            );
        }
    );

    ok $success, "https connection success";
};

done_testing;
