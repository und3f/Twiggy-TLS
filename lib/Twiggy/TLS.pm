package Twiggy::TLS;

use strict;
use warnings;

use 5.008_001;
our $VERSION = '0.0001_2';

1;
__END__

=head1 NAME

Twiggy::TLS - TLS support for Twiggy server

=head1 SYNOPSIS

    plackup --server Twiggy::TLS --ssl_key=key.pem --ssl_cert=cert.pem

    use Twiggy::Server::TLS;

    my $server = Twiggy::Server::TLS->new(
        host     => $host,
        port     => $port,
        ssl_key  => $key_filename,
        ssl_cert => $cert_filename
    );
    $server->register_service($app);

    AE::cv->recv;

=head1 DESCRIPTION

Twiggy::TLS is a TLS connection support for Twiggy server.

=head1 LICENSE

This module is licensed under the same terms as Perl itself.

=head1 AUTHOR

Sergey Zasenko

=head1 SEE ALSO

L<Twiggy>

=cut
