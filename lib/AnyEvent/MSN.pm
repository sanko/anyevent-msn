package AnyEvent::MSN 0.001;
{
    use lib '../../lib';
    use 5.012;
    use Moose;
    use Moose::Util::TypeConstraints;
    use AnyEvent qw[];
    use AnyEvent::Socket qw[];
    use AnyEvent::Handle qw[];
    use AnyEvent::HTTP qw[];
    use AnyEvent::MSN::Protocol;
    use MIME::Base64 qw[];
    use XML::Simple qw[];
    use Ouch;
    use Data::Dump;

    # Basic connection info
    has host => (is      => 'ro',
                 writer  => '_set_host',
                 isa     => 'Str',
                 clearer => '_reset_host',
                 builder => '_build_host'
    );
    sub _build_host {'messenger.hotmail.com'}
    has port => (is      => 'ro',
                 writer  => '_set_port',
                 isa     => 'Int',
                 clearer => '_reset_port',
                 builder => '_build_port'
    );
    sub _build_port {1863}

    # Client info for MSNP21
    has protocol_version => (
        is  => 'ro',
        isa => subtype(
            as 'Str' => where {m[^(?:MSNP\d+\s*)+$]} => message {
                'Protocol versions look like: MSNP18 MSNP21';
            }
        ),
        writer  => '_set_protocol_version',
        clearer => '_reset_protocol_version',
        builder => '_build_protocol_version'
    );
    sub _build_protocol_version {'MSNP21'}
    has product_id =>
        (is => 'ro', isa => 'Str', default => 'PROD0120PW!CCV9@');
    has product_key =>
        (is => 'ro', isa => 'Str', default => 'C1BX{V4W}Q3*10SM');
    has locale_id   => (is => 'ro', isa => 'Str', default => '0x0409');
    has os_type     => (is => 'ro', isa => 'Str', default => 'winnt');
    has os_ver      => (is => 'ro', isa => 'Str', default => '6.1.0');
    has arch        => (is => 'ro', isa => 'Str', default => 'i386');
    has client_name => (is => 'ro', isa => 'Str', default => 'WLMSGRBETA');
    has client_version =>
        (is => 'ro', isa => 'Str', default => '15.4.3002.0810');
    has client_string => (is => 'ro', isa => 'Str', default => 'WLMSGRBETA');
    has guid => (
        is     => 'ro',
        => isa => subtype(
            as 'Str' => where {
                my $hex = qr[[\da-f]];
                m[{$hex{8}(?:-$hex{4}){3}-$hex{12}}$];
            } => message {
                'Malformed GUID. Should look like: {12345678-abcd-1234-abcd-123456789abc}';
            }
        ),
        builder => '_build_guid'
    );

    sub _build_guid {

        sub _ {
            join '', map { ('a' .. 'f', 0 .. 9)[rand 15] } 1 .. shift;
        }
        sprintf '{%8s-%4s-%4s-%4s-%12s}', _(8), _(4), _(4), _(4), _(12);
    }

    # Authentication Info (from user)
    has username => (
        is  => 'ro',
        isa => subtype(
            as 'Str' => where {
                my $atom       = qr{[a-zA-Z0-9_!#\$\%&'*+/=?\^`{}~|\-]+};
                my $dot_atom   = qr{$atom(?:\.$atom)*};
                my $quoted     = qr{"(?:\\[^\r\n]|[^\\"])*"};
                my $local      = qr{(?:$dot_atom|$quoted)};
                my $quotedpair = qr{\\[\x00-\x09\x0B-\x0c\x0e-\x7e]};
                my $domain_lit =
                    qr{\[(?:$quotedpair|[\x21-\x5a\x5e-\x7e])*\]};
                my $domain    = qr{(?:$dot_atom|$domain_lit)};
                my $addr_spec = qr{$local\@$domain};
                $_ =~ $addr_spec;
            } => message {
                'An MSN Passport looks like an email address: you@hotmail.com';
            }
        ),
        required => 1
    );
    has password => (is => 'ro', isa => 'Str', required => 1);

    # Callbacks
    has cmd_cb => (is        => 'ro',
                   isa       => 'CodeRef',
                   predicate => '_has_cmd_cb',
                   writer    => '_set_cmd_cb',
                   clearer   => '_reset_cmd_cb'
    );
    has on_error => (is        => 'ro',
                     isa       => 'CodeRef',
                     predicate => '_has_on_error',
                     writer    => '_set_on_error'
    );

    # AE stuff
    has connect_queue => (is      => 'ro',
                          isa     => 'ArrayRef[AnyEvent::CondVar]',
                          builder => '_build_connect_queue'
    );
    sub _build_connect_queue { [] }
    has sock => (is        => 'ro',
                 isa       => 'AnyEvent::Util::guard',
                 predicate => '_has_sock',
                 writer    => '_set_sock',
                 clearer   => '_reset_sock'
    );
    has handle => (is        => 'ro',
                   isa       => 'AnyEvent::Handle',
                   predicate => '_has_handle',
                   writer    => '_set_handle',
                   clearer   => '_reset_handle'
    );
    has soap => (is        => 'ro',
                 isa       => 'Object',
                 predicate => '_has_soap',
                 writer    => '_set_soap',
                 clearer   => '_reset_soap'
    );

    # Internals
    has tid => (is      => 'ro',
                isa     => 'Int',
                default => 1,
                traits  => ['Counter'],
                handles => {'_inc_tid' => 'inc'}
    );
    after tid => sub { shift->_inc_tid };    # Auto inc
    has redirect => (is      => 'ro',
                     isa     => 'Str',
                     writer  => '_set_redirect',
                     clearer => '_reset_redirect',
                     builder => '_build_redirect'
    );
    sub _build_redirect {0}
    has SSOsites => (
        is      => 'ro',                     # Single Sign On
        isa     => 'ArrayRef[ArrayRef]',
        traits  => ['Array'],
        default => sub {
            [['http://Passport.NET/tb',   ''],
             ['messengerclear.live.com',  'MBI_KEY_OLD'],
             ['messenger.msn.com',        '?id=507'],
             ['messengersecure.live.com', 'MBI_SSL'],
             ['contacts.msn.com',         'MBI'],
             ['storage.msn.com',          'MBI'],
             ['sup.live.com',             'MBI']
            ];
        }
    );

    # Structures from NS
    has policy => (is        => 'ro',
                   isa       => 'HashRef',
                   predicate => '_has_policy',
                   writer    => '_set_policy',
                   clearer   => '_reset_policy'
    );
    has auth => (is        => 'ro',
                 isa       => 'HashRef',
                 predicate => '_has_auth',
                 writer    => '_set_auth'
    );

    #
    sub cleanup {
        my $s = shift;
        $s->_reset_cmd_cb;
        $s->_reset_sock;
        $s->_reset_soap;
        $s->_reset_redirect;
        $s->_reset_policy;
        $s->on_error->(@_) if $s->_has_on_error and !shift;
    }

    #
    sub connect {
        my $s  = shift;
        my $cv = AE::cv;
        if (@_) {
            $cv = pop if UNIVERSAL::isa($_[-1], 'AnyEvent::CondVar');
            $s->connect_queue->push([$cv, @_]);
        }
        return $cv if $s->_has_sock;
        $s->_set_sock(
            AnyEvent::Socket::tcp_connect(
                $s->host,
                $s->port,
                sub {
                    my $fh = shift
                        or do {
                        my $err =
                            "Can't connect MSN Dispatch Server server for authentication: $!";
                        $s->cleanup($err);
                        $cv->croak($err);
                        return;
                        };

                    #
                    $s->_set_handle(
                        AnyEvent::Handle->new(
                            fh => $fh,

                            #on_connect => sub { $s->handle = $s->handle },
                            on_drain => sub { },
                            on_error => sub {
                                $_[0]->destroy;
                                $s->cleanup($_[2]) if $_[1];
                            },
                            on_eof => sub {
                                $_[0]->destroy;
                                $s->cleanup('connection closed');
                            },
                            on_read => sub {
                                warn 'READ!!!!!!!!!!!!!!!!';
                                die shift->rbuf;
                            },
                            on_write => sub {...}
                        )
                    );

                    #
                    $s->_negotiate_protocol_version;
                    $s->handle->push_read('AnyEvent::MSN::Protocol' => $s);

                    #
                    $s->_set_cmd_cb(
                        sub
                        {    # XXX - This should handle everything after login
                            ...;
                            my $command = lc shift;
                            return $cv;
                        }
                    );

                    #for my $queue (@{$s->connect_queue || []}) {
                    #    my ($cv, @args) = @$queue;
                    #    $s->cmd_cb->(@args, $cv);
                    #}
                    return 1;
                }
            )
        );
        return $cv;
    }

    sub _negotiate_protocol_version {
        my $s = shift;
        $s->handle->push_write('AnyEvent::MSN::Protocol' => 'VER %d %s',
                               $s->tid, $s->protocol_version);

        # Expect VER ... in reply
    }

    sub _send_client_info {
        my $s = shift;
        my ($protver) = ($s->protocol_version =~ m[MSNP(\d+)]);
        $s->handle->push_write(
              'AnyEvent::MSN::Protocol' => 'CVR %d %s %s %s %s %s %s %s %s%s',
              $s->tid, $s->locale_id, $s->os_type, $s->os_ver, $s->arch,
              $s->client_name, $s->client_version, $s->client_string,
              $s->username, ($protver >= 21 ? ' ' . $s->redirect : '')
        );
    }

    sub _handle_packet_cvr {    #- Continue authentication
        my $s = shift;
        my ($cmd, $tid, $r, $min_a, $min_b, $url_dl, $url_info) = @_;

        # We don't do anything with this yet but...
        # The first parameter is a recommended version of
        # the client for you to use, or "1.0.0000" if your
        #   client information is not recognised.
        # The second parameter is identical to the first.
        # The third parameter is the minimum version of the
        #   client it's safe for you to use, or the current
        #   version if your client information is not
        #   recognised.
        # The fourth parameter is a URL you can download the
        #   recommended version of the client from.
        # The fifth parameter is a URL the user can go to to
        #   get more information about the client.
        $s->_send_passport;    # For the first time
    }

    sub _send_passport {
        my $s = shift;
        $s->handle->push_write('AnyEvent::MSN::Protocol' => 'USR %d SSO I %s',
                               $s->tid, $s->username);

        #$s->_expect_policy;
    }

    sub _init_soap {
        my ($s, $policy, $nonce) = @_;
        my $x = 0;
        my $sites = join '', map {
            sprintf <<'END', $x++, @$_ } @{$s->SSOsites};
            <wst:RequestSecurityToken Id="RST%d">
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>%s</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wsse:PolicyReference URI="%s">
                </wsse:PolicyReference>
            </wst:RequestSecurityToken>
END

        #
        $s->_set_soap(
            AnyEvent::HTTP::http_request(
                'POST' => ($s->username =~ m[\@msn.com$]i
                           ? 'https://msnia.login.live.com/pp550/RST.srf'
                           : 'https://login.live.com/RST.srf'
                ),
                headers => {
                         'user-agent' => 'MSNPM 1.0',
                         'content-type' =>
                             'application/soap+xml; charset=utf-8; action=""',
                         'Expect'     => '100-continue',
                         'connection' => 'Keep-Alive'
                },
                timeout    => 30,
                persistent => 1,

                # XXX - XML::Simple generates XML MSN doesn't like. Ideas?
                body => sprintf( <<'END', $s->username, $s->password, $sites),
<?xml version="1.0" encoding="UTF-8"?>
<Envelope   xmlns="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext"
            xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
            xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing"
            xmlns:wssc="http://schemas.xmlsoap.org/ws/2004/04/sc"
            xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
    <Header>
        <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo">
            <ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp>
            <ps:BinaryVersion>4</ps:BinaryVersion>
            <ps:UIVersion>1</ps:UIVersion>
            <ps:Cookies></ps:Cookies>
            <ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams>
        </ps:AuthInfo>
            <wsse:Security><wsse:UsernameToken Id="user">
                <wsse:Username>%s</wsse:Username>
                <wsse:Password>%s</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </Header>
    <Body>
        <ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">
           %s
        </ps:RequestMultipleSecurityTokens>
    </Body>
</Envelope>
END
                sub {
                    $s->_set_auth(XML::Simple::XMLin(shift));
                    $s->_send_login($policy, $nonce);
                    return 1;
                }
            )
        );
    }

    sub _send_login {
        my ($s, $policy, $nonce) = @_;
        for my $token (@{  $s->auth->{'S:Body'}
                               {'wst:RequestSecurityTokenResponseCollection'}
                               {'wst:RequestSecurityTokenResponse'}
                       }
            )
        {
            if ($policy =~ m[MBI]
                && defined $token->{'wst:RequestedSecurityToken'}
                {'wsse:BinarySecurityToken'})
            {   my $token_ =
                    $token->{'wst:RequestedSecurityToken'}
                    {'wsse:BinarySecurityToken'}{'content'};
                $token_ =~ s/&/&amp;/sg;
                $token_ =~ s/</&lt;/sg;
                $token_ =~ s/>/&gt;/sg;
                $token_ =~ s/"/&quot;/sg;
                my ($protver) = ($s->protocol_version =~ m[MSNP(\d+)]);
                $s->handle->push_write(
                          'AnyEvent::MSN::Protocol' => 'USR %d SSO S %s %s%s',
                          $s->tid,
                          $token->{'wst:RequestedSecurityToken'}
                              {'wsse:BinarySecurityToken'}{'content'},
                          AnyEvent::MSN::Protocol::SSO(
                                           $nonce,
                                           $token->{'wst:RequestedProofToken'}
                                               {'wst:BinarySecret'}
                          ),
                          ($protver >= 21 ? ' ' . $s->guid : '')
                );
                $s->_expect_OK;
                last;
            }
            elsif ($policy =~ m[^\?]) {
                ...;
            }
        }
    }

    #
    sub _expect_OK {    # Login complete?
        my $s = shift;

#$s->handle->push_read(
#    'AnyEvent::MSN::Protocol' => sub {
#        #...;
#        #$s->handle->push_write(
#        #'AnyEvent::MSN::Protocol' =>
#        #    'QRY %d %s 32\r\n%s', $s->tid, $s->product_id, '19628948c65320d8468204e6c0f668b4'
#    #);
#    return 1
#    }
#);
    }

    sub _handle_packet_chl {
        my $s = shift;
        $s->handle->push_write('AnyEvent::MSN::Protocol' => 'QRY %d %s 32',
                               $s->tid, $s->username);
    }

    sub _handle_packet_gcf {
        my ($s, $tid, $len, $r) = @_;
        if ($tid == 0) {    # probably Policy list
            $s->_set_policy($r->{Policy});
            for (@{$s->policy->{SHIELDS}{config}{block}{regexp}{imtext}}) {
                my $regex = MIME::Base64::decode_base64($_);

                #warn 'Blocking ' . qr[$regex];
            }

            # Expect USR Token
        }
        else {
            ...;
        }
    }

    sub _handle_packet_usr {
        my ($s, $tid, $subtype, $_s, $policy, $nonce) = @_;
        if ($subtype eq 'SSO') {
            $s->_init_soap($policy, $nonce);
        }
        elsif ($subtype eq 'OK') {

            # XXX - logged in okay. What now?
        }
        else {
            ...;
        }
    }

    sub _handle_packet_ver {
        my ($s, $tid, $r) = @_;
        $s->_set_protocol_version($r);
        $s->_send_client_info;
    }

    sub _handle_packet_xfr {
        my $s = shift;
        my ($tid, $type, $addr, $u, $d, $redirect) = @_;
        $s->cleanup('being redirected', 1);
        $s->handle->push_write('OUT');
        $s->handle->destroy;
        $s->_set_redirect($redirect);
        my ($host, $port) = ($addr =~ m[^(.+):(\d+)$]);
        $s->_set_host($host);
        $s->_set_port($port);
        $s->connect();
    }

    #
    __PACKAGE__->meta->make_immutable();
}
1;

=pod

=head1 NAME

AnyEvent::MSN - Exactly what you're expecting...

=head1 Description

TODO

=head1 See Also

=over

=item L<Net::MSN|Net::MSN>

=item L<MSN::PersonalMessage|MSN::PersonalMessage>

=item L<POE::Component::Client::MSN|POE::Component::Client::MSN>

=item L<Net::Msmgr::Session|Net::Msmgr::Session>

=back

=head1 Legal... etc.

Blah

=cut
