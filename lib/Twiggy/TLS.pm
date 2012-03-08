package Twiggy::TLS;

use strict;
use warnings;

use 5.008_001;
our $VERSION = '0.0001_3';

1;
__END__

=head1 NAME

Twiggy::TLS - TLS support for Twiggy server

=head1 SYNOPSIS

    plackup --server Twiggy::TLS --ssl-key key.pem --ssl-cert cert.pem


Other possible options are C<--ssl-verify> and C<--ssl-ca>. See L</ATTRIBUTES> for
more details.

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

Twiggy::TLS extends Twiggy with a TLS support.

=head1 ATTRIBUTES

All files must be in PEM format. You can merge multiply entities in a one file
(like server key and certificate).

=head2 ssl_key

Path to a file that contains server private key.

=head2 ssl_cert

Path to a file that contains server certificate.

=head2 ssl_verify

Controls the verification of the peer identity. Possible values are:

=over 4

=item C<off>

Default. Disable peer verification.

=item C<on>

Request peer certificate and verify it against CA. You can specify CA
certificate with C<ssl_ca> option. Client's certificate C<Common Name> field
stored in C<$env-E<gt>{HTTP_SSL_CLIENT_S_DN_CN}>.

=item C<optional>

Same as C<on>, but allows users that has not passed verification.

=back

=head2 ssl_ca

Path to file that contains CA certificate. Used for peer verification.

=head1 DEBUGGING

You can set the C<TWIGGY_DEBUG> environment variable to get diagnostic
information.

=head1 LICENSE

This module is licensed under the same terms as Perl itself.

=head1 AUTHOR

Sergey Zasenko

=head1 SEE ALSO

L<Twiggy>

=cut
