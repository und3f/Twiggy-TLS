#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use Test::TCP;
use Plack::Loader;
use LWP::UserAgent;
use File::Temp;

my $pem = do {
    local $/;
    <DATA>;
};

my ($pem_fh, $pem_filename) =
  File::Temp::tempfile(SUFFIX => '.pem', UNLINK => 1);

print $pem_fh $pem;
$pem_fh->close;

subtest 'tls connection' => sub {
    my $success;

    test_tcp(
        client => sub {
            my $port = shift;

            alarm 2;
            local $SIG{ALRM} = sub {die};

            my $ua  = LWP::UserAgent->new(ssl_opts => {verify_hostname => 0});
            my $res = $ua->get("https://127.0.0.1:$port");
            $success = $res->is_success;
        },
        server => sub {
            my $port   = shift;
            my $server = Plack::Loader->load(
                'Twiggy::TLS',
                port     => $port,
                host     => '127.0.0.1',
                ssl_key  => $pem_filename,
                ssl_cert => $pem_filename,
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

__END__
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCixn0Gp7R3Yv9HHXqDh0W1igoaSP4POIVPEp8Jq0jGUdMe+rwy
yjA2KISEqCsUT8eo9jNsdz+CvpBCZguR/YhnQ/afZYxp0XZBqecmHrsFn3j0W+AD
sD+aoELRG9DnLRSDI3ACCAMP5bJ1LIRp6JtPrgPVth+tz4DtKOKolQJ+zQIDAQAB
AoGASXDmvhbyfJ8k8HAjc66XzBWxAzUFs9Zbh1aufM1UM259o8+bFAtXf0f+ql+5
uBtaySf0Aa8374SNT/f8pmzOmpiXMvYRz8Z5Gc6JYpYd/PrCoSCGtP+NdCvk7Y5c
eUmmpiEto4+fgCAKrtqc5jm8eBWn/yNhQNDBVJ9qX+kXQOECQQDVBLvBZaECSMTm
djKuPlZ93cmyI7g+TURTl2N08fz4xQVVbo5+AV0GsEZupBpTgrHpLTk8gKP/nfdR
9KWZldbZAkEAw55+SqrVTv4cI0fMvC0t8Wl46zTkY9tK65TGnbO1DbTQh9qs+NwH
+v3uu47ef5w/73xLtDjQouz//0z5rgF3FQJAfrmOKQOYwY8g9CmlBNu5ALAM6Zku
ZoH4//G0DUJYyHYNMkHPK08MVIpRnEisELpTtPBeeIvfBJapJ2xvh+sIIQJASeY4
I5EB4EOS8akQKQ6QSqDjs0dZ+HdBiFm95pmbDkB+frQXoDPPN/xyEZzZZS/r31b/
amgEOWh7FUFJGXkoOQJBALfOgsiss0lASlOXAg1rwO4m2OaDiaEde01PLcSjIaKl
Qfbzc7ZYF+fGDsHHlD5Kgj1CGaWCVVHqCv4UHSrA/gM=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICKTCCAZICCQDFxHnOjdmTTjANBgkqhkiG9w0BAQUFADBZMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTIwMTE0MTgzMjMwWhcN
NzUxMTE0MTIwNDE0WjBZMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0
ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQDDAls
b2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKLGfQantHdi/0cd
eoOHRbWKChpI/g84hU8SnwmrSMZR0x76vDLKMDYohISoKxRPx6j2M2x3P4K+kEJm
C5H9iGdD9p9ljGnRdkGp5yYeuwWfePRb4AOwP5qgQtEb0OctFIMjcAIIAw/lsnUs
hGnom0+uA9W2H63PgO0o4qiVAn7NAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEATDGA
dYRl5wpsYcpLgNzu0M4SENV0DAE2wNTZ4LIR1wxHbcxdgzMhjp0wwfVQBTJFNqWu
DbeIFt4ghPMsUQKmMc4+og2Zyll8qev8oNgWQneKjDAEKKpzdvUoRZyGx1ZocGzi
S4LDiMd4qhD+GGePcHwmR8x/okoq58xZO/+Qygc=
-----END CERTIFICATE-----
