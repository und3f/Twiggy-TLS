package Twiggy::Server::TLS;

use strict;
use warnings;

use base 'Twiggy::Server';

use IO::Socket::SSL;
require Carp;

use constant DEBUG     => $ENV{TWIGGY_DEBUG};
use constant TLS_WRITE => IO::Socket::SSL::SSL_WANT_WRITE();
use constant TLS_READ  => IO::Socket::SSL::SSL_WANT_READ();

sub new {
    my $class = shift;

    my $self = $class->SUPER::new(@_);

    my %tls = (
        SSL_server      => 1,

        SSL_version     => $self->{ssl_version} || 'tlsv1',
        SSL_cipher_list => $self->{ssl_ciphers} || 'HIGH:!aNULL:!MD5',

        SSL_key_file    => $self->{ssl_key},
        SSL_cert_file   => $self->{ssl_cert},
        SSL_ca_file     => $self->{ssl_ca},
    );

    if (my $verify = $self->{ssl_verify}) {
        if ($verify eq 'off') {
        }
        elsif ($verify eq 'on') {
            $tls{SSL_verify_mode} = 0x03;
        }
        elsif ($verify eq 'optional') {
            $tls{SSL_verify_mode} = 0x01;
        }
        else {
            Carp::croak qq(Invalid ssl_verify value "$verify");
        }
    }

    $self->{_tls_opts} = \%tls;

    IO::Socket::SSL::SSL_Context->new(%tls)
      or Carp::croak(
        "TLS context initialization failed: " . IO::Socket::SSL::errstr);

    if (my $server_ready_orig = $self->{server_ready}) {
        $self->{server_ready} = sub {
            my $args = shift;
            $args->{proto} = 'https';
            $server_ready_orig->($args);
        };
    }

    $self;
}

sub _accept_handler {
    my $self = shift;

    my $super = $self->SUPER::_accept_handler(@_);

    return sub {
        my ($sock, $peer_host, $peer_port) = @_;

        DEBUG
          && warn "$sock TLS/SSL connection accepted $peer_host:$peer_port\n";
        return unless $sock;

        $self->{exit_guard}->begin;

        my $ssl_sock = IO::Socket::SSL->start_SSL(
            $sock,
            SSL_startHandshake => 0,

            SSL_error_trap => sub {
                my ($sock, $error) = @_;

                $self->{exit_guard}->end;
                delete $self->{ssl_guard}->{$sock};
                $sock->close(SSL_ctx_free => 1);
                DEBUG && warn "$sock TLS/SSL error: $error\n";
            },
            %{$self->{_tls_opts}}
        );

        $self->_setup_tls(
            $ssl_sock,
            0,
            sub {
                $self->{exit_guard}->end;

                DEBUG && warn "$sock TLS/SSL connection established\n";
                $super->($sock, $peer_host, $peer_port);
            }
        );

      }
}

sub _run_app {
    my ($self, $app, $env, $sock) = @_;

    $env->{'psgi.url_scheme'} = 'https';
    $env->{'HTTP_SSL_CLIENT_S_DN_CN'} = $sock->peer_certificate('cn');

    $self->SUPER::_run_app($app, $env, $sock);
}

sub _setup_tls {
    my ($self, $sock, $read, $cb) = @_;

    $self->{ssl_guard}->{$sock} = AnyEvent->io(
        fh   => $sock,
        poll => $read ? "r" : "w",
        cb   => sub {
            delete $self->{ssl_guard}->{$sock};
            if ($sock->accept_SSL) {
                return $cb->();
            }

            my $error = $IO::Socket::SSL::SSL_ERROR;

            return unless $error == TLS_READ || $error == TLS_WRITE;

            $self->_setup_tls($sock, $error == TLS_READ, $cb);
        }
    );
}

1;
