package Twiggy::Server::TLS;

use strict;
use warnings;

use base 'Twiggy::Server';

use IO::Socket::SSL;
require Carp;

# $IO::Socket::SSL::DEBUG = 5;

use constant DEBUG     => $ENV{TWIGGY_DEBUG};
use constant TLS_WRITE => IO::Socket::SSL::SSL_WANT_WRITE();
use constant TLS_READ  => IO::Socket::SSL::SSL_WANT_READ();

sub new {
    my $class = shift;

    my $self = $class->SUPER::new(@_);

    Carp::croak 'ssl_key_file required'
      unless exists $self->{ssl_key};

    Carp::croak 'ssl_cert_file required'
      unless exists $self->{ssl_cert};

    $self;
}

sub _accept_handler {
    my ($self, $app, $is_tcp) = @_;

    my $super = $self->SUPER::_accept_handler($app, $is_tcp);

    return sub {
        my ($sock, $peer_host, $peer_port) = @_;

        DEBUG
          && warn "$sock TLS/SSL connection accepted $peer_host:$peer_port\n";
        return unless $sock;

        $self->{exit_guard}->begin;

        my $ssl_sock = IO::Socket::SSL->start_SSL(
            $sock,
            SSL_server         => 1,
            SSL_startHandshake => 0,

            SSL_error_trap => sub {
                my ($sock, $error) = @_;

                $self->{exit_guard}->end;
                delete $self->{ssl_guard}->{$sock};
                $sock->close;
                DEBUG && warn "$sock TLS/SSL error: $error\n";
            },

            SSL_key_file  => $self->{ssl_key},
            SSL_cert_file => $self->{ssl_cert},
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
