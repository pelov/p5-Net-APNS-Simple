package Net::APNS::Simple;
use 5.008001;
use strict;
use warnings;
use Carp ();
use JSON;
use Moo;
use Protocol::HTTP2::Client;
use Protocol::HTTP2::Constants qw(const_name :frame_types :settings);
use IO::Socket::SSL qw();
use IO::Async::Loop;
use IO::Async::Stream;
use IO::Async::Timer::Countdown;

our $VERSION = "0.06";

has [qw/auth_key key_id team_id bundle_id development/] => (
    is => 'rw',
);

has [qw/cert_file key_file passwd_cb/] => (
    is => 'rw',
);

has [qw/proxy/] => (
    is => 'rw',
    default => $ENV{https_proxy},
);

has [qw/timeout/] => (
    is => 'rw',
    default => 10,
);

has apns_priority => (
    is => 'rw',
    default => 10,
);

sub algorithm {'ES256'}

sub _host {
    my ($self) = @_;
    return 'api.' . ($self->development ? 'sandbox.' : '') . 'push.apple.com'
}

sub _port {443}

sub BUILD {
    my ($self, $args) = @_;

    $self->connect();
}


sub _socket {
    my ($self) = @_;
    if (!$self->{_socket} || !$self->{_socket}->opened){
        my %ssl_opts = (
             # openssl 1.0.1 support only NPN
             SSL_npn_protocols => ['h2'],
             # openssl 1.0.2 also have ALPN
             SSL_alpn_protocols => ['h2'],
             SSL_version => 'TLSv1_2',
        );
        for (qw/cert_file key_file passwd_cb/) {
            $ssl_opts{"SSL_$_"} = $self->{$_} if defined $self->{$_};
        }

        my ($host,$port) = ($self->_host, $self->_port);

        my $socket;
        if ( my $proxy = $self->proxy ) {
            $proxy =~ s|^http://|| or die "Invalid proxy $proxy - only http proxy is supported!\n";
            require Net::HTTP;
            $socket = Net::HTTP->new(PeerAddr => $proxy) || die "error connecting to $proxy: $@\n";
            $socket->write_request(
                CONNECT => "$host:$port",
                Host => "$host:$port",
                Connection => "Keep-Alive",
                'Proxy-Connection' => "Keep-Alive",
            );
            my ($code, $mess, %h) = $socket->read_response_headers;
            $code eq '200' or die "proxy error: $code $mess\n";

            IO::Socket::SSL->start_SSL(
                $socket,
                # explicitly set hostname we should use for SNI
                SSL_hostname => $host,
                %ssl_opts,
            ) or die "$host start_SSL error: $IO::Socket::SSL::SSL_ERROR\n";
        }
        else {
            # TLS transport socket
            $socket = IO::Socket::SSL->new(
                PeerHost => $host,
                PeerPort => $port,
                %ssl_opts,
            ) or die $! || $IO::Socket::SSL::SSL_ERROR;
        }
        $self->{_socket} = $socket;

        # non blocking
        $self->{_socket}->blocking(0);
    }
    return $self->{_socket};
}

sub _client {
    my ($self) = @_;
    $self->{_client} ||= Protocol::HTTP2::Client->new(keepalive => 1);
    return $self->{_client};
}

sub write_frames {
    my $socket = shift;
    my $client = shift;

    my $buf;
    while ( my $frame = $client->next_frame ) {
        $buf .= $frame;
    }

    my $len = length $buf;
    my $n = 0;
    while ($len - $n) {
        my $i = syswrite $socket, $buf, $len - $n, $n;
        if ( defined $i ) {
            $n += $i;
        }
        #elsif ($!{EINTR}) {
        #    redo;
        #}
        else {
            #return $n ? $n : undef;
            return;
        }
    }
    return $n;
}

sub connect {
    my ($self) = @_;

    my $host = $self->_host;
    my $socket = $self->_socket;
    my $client = $self->_client;

    # Send HTTP/2 client preface
    my $con = $client->{con};
    if ( !$con->preface ) {
        $con->enqueue_raw( $con->preface_encode );
        $con->enqueue( SETTINGS, 0, 0, $self->{settings} );
        $con->preface(1);
    }

    write_frames($socket, $client) or die "$!\n";

    my $loop = IO::Async::Loop->new;
    my $future = $loop->new_future;
    my $timer = IO::Async::Timer::Countdown->new(
                                                 delay => $self->timeout,
                                                 on_expire => sub {
                                                     $future->fail("timeout connecting to $host\n", connect => $host)
                                                 },
                                                );
    my $stream = IO::Async::Stream->new(
                                        read_handle  => $socket,
                                        on_read => sub {
                                            my ( $stream, $buffref, $eof ) = @_;

                                            $client->feed($$buffref) if ref $buffref eq 'SCALAR';

                                            if ( $eof ) {
                                                $future->fail("EOF during connect to $host\n", connect => $host);
                                            }
                                            elsif (my $goaway = $con->goaway) {
                                                my $err;
                                                if (ref $goaway eq 'HASH') {
                                                    if ($goaway->{data} ne '') {
                                                        $err = $goaway->{data}
                                                    }
                                                    elsif ($goaway->{error} > 0) {
                                                        my $err = const_name( 'errors', $goaway->{error} );
                                                    }
                                                }
                                                $err ||= 'goaway';
                                                $err .= " during connect to $host";

                                                $future->fail("$err\n", connect => $host);
                                            }
                                            elsif ($con->shutdown) {
                                                $future->fail("shutdown during connect to $host\n", connect => $host);
                                            }
                                            elsif ($con->dec_setting(SETTINGS_MAX_CONCURRENT_STREAMS)) {
                                                $timer->stop;
                                                $future->done(1);
                                            }

                                            return 0;
                                        }
                                       );

    $loop->add( $timer->start );
    $loop->add( $stream );

    # Will throw an exception if $future->fail is called above
    my $res = $future->get;
    $loop->remove($stream);
    return $res;
}

sub prepare {
    my ($self, $device_token, $payload) = @_;
    my @headers = (
        'apns-topic' => $self->bundle_id,
    );

    for (qw/apns_id apns_priority apns_expiration apns_collapse_id/) {
        my $v = delete $payload->{$_};
        next unless defined $v;
        my $k = $_;
        $k =~ s/_/-/g;
        push @headers, $k => $v;
    }

    if ($self->team_id and $self->auth_key and $self->key_id) {
        require Crypt::PK::ECC;
        # require for treat pkcs#8 private key
        Crypt::PK::ECC->VERSION(0.059);
        require Crypt::JWT;
        my $claims = {
            iss => $self->team_id,
            iat => time,
        };
        my $jwt = Crypt::JWT::encode_jwt(
            payload => $claims,
            key => [$self->auth_key],
            alg => $self->algorithm,
            extra_headers => {
                kid => $self->key_id,
            },
        );
        push @headers, authorization => sprintf('bearer %s', $jwt);
    }
    my $path = sprintf '/3/device/%s', $device_token;
    return {
            ':scheme' => 'https',
            ':authority' => join(":", $self->_host, $self->_port),
            ':path' => $path,
            ':method' => 'POST',
            headers => \@headers,
            data => JSON::encode_json($payload),
           };
}

sub notify {
    my ($self,$req) = @_;

    my $host = $self->_host;
    my $loop = IO::Async::Loop->new;
    my $future = $loop->new_future;
    my $timer = IO::Async::Timer::Countdown->new(
                                                 delay => $self->timeout,
                                                 on_expire => sub {
                                                     $future->fail( "timeout reading from $host\n", read => $host )
                                                 }
                                                );
    $req->{ on_done } = sub {
        $timer->stop;
        $future->done( @_ );
    };

    my $socket = $self->_socket;
    my $client = $self->_client;
    $client->request(%$req);

    write_frames($socket, $client) or die "$!\n";

    my $stream = IO::Async::Stream->new(
                                        read_handle  => $socket,
                                        on_read => sub {
                                            my ( $self, $buffref, $eof ) = @_;

                                            $client->feed($$buffref);

                                            if ( $eof ) {
                                                print "EOF\n";
                                            }

                                            return 0;
                                        }
                                       );

    $loop->add( $timer->start );
    $loop->add( $stream );

    return $future->get;
}

sub DEMOLISH {
    my ($self,$global) = @_;

    my $socket = $self->{_socket};
    if ( $socket && $socket->connected ) {
        if ( my $client = $self->{_client} ) {
            $client->close;

            write_frames($socket,$self->_client) or warn $!;

            while ( sysread $socket, my $data, 4096 ) {
                $self->_client->feed($data);
            }

            undef $self->{_client};
        }

        $socket->close();
    }
}

1;
__END__

=encoding utf-8

=head1 NAME

Net::APNS::Simple - APNS Perl implementation

=head1 DESCRIPTION

A Perl implementation for sending notifications via APNS using Apple's new HTTP/2 API.
This library uses Protocol::HTTP2::Client as http2 backend.
And it also supports multiple stream at one connection.
(It does not correspond to parallel stream because APNS server returns SETTINGS_MAX_CONCURRENT_STREAMS = 1.)

=head1 SYNOPSIS

    use Net::APNS::Simple;

    # With provider authentication tokens
    my $apns = Net::APNS::Simple->new(
        # enable if development
        # development => 1,
        auth_key => '/path/to/auth_key.p8',
        key_id => 'AUTH_KEY_ID',
        team_id => 'APP_PREFIX',
        bundle_id => 'APP_ID',
    );

    # With SSL certificates
    my $apns = Net::APNS::Simple->new(
        # enable if development
        # development => 1,
        cert_file => '/path/to/cert.pem',
        key_file => '/path/to/key.pem',
        passwd_cb => sub { return 'key-password' },
        bundle_id => 'APP_ID',
    );

    # prepare request
    my $req = $apns->prepare('DEVICE_ID',{
            aps => {
                alert => 'APNS message: HELLO!',
                badge => 1,
                sound => "default",
                # SEE: https://developer.apple.com/jp/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/TheNotificationPayload.html,
            },
        }
    );

    # send notification
    my ($header, $content) = $apns->notify($req);

    require Data::Dumper;
    print Dumper $header;

    # $VAR1 = [
    #           ':status',
    #           '200',
    #           'apns-id',
    #           '791DE8BA-7CAA-B820-BD2D-5B12653A8DF3'
    #         ];

    print Dumper $content;

    # $VAR1 = undef;

=head1 METHODS

=head2 my $apns = Net::APNS::Simple->new(%arg)

=over

=item development : bool

Switch API's URL to 'api.sandbox.push.apple.com' if enabled.

=item auth_key : string

Private key file for APNS obtained from Apple.

=item team_id : string

Team ID (App Prefix)

=item bundle_id : string

Bundle ID (App ID)

=item cert_file : string

SSL certificate file.

=item key_file : string

SSL key file.

=item passwd_cb : sub reference

If the private key is encrypted, this should be a reference to a subroutine that should return the password required to decrypt your private key.

=item proxy : string

URL of a proxy server. Default $ENV{https_proxy}. Pass undef to disable proxy.

=back

    All properties can be accessed as Getter/Setter like `$apns->development`.

=head2 $apns->prepare($DEVICE_ID, $PAYLOAD);

Prepare notification.

Payload please refer: https://developer.apple.com/library/content/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/PayloadKeyReference.html#//apple_ref/doc/uid/TP40008194-CH17-SW1.

In addition, payload can contain the following keys which specify headers and are deleted from the final payload.

=item apns_id : string

Canonical UUID that identifies the notification (apns-id header).

=item apns_expiration : number

Sets the apns-expiration header.

=item apns_priority : number

Sets the apns-priority header. Default 10.

=item apns_collapse_id : string

Sets the apns-collapse-id header.

=head2 $apns->notify($req);

Execute notification.

=head1 LICENSE

Copyright (C) Tooru Tsurukawa.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Tooru Tsurukawa E<lt>rockbone.g at gmail.comE<gt>

=cut

