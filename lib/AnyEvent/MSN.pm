package AnyEvent::MSN 0.001;
{
    use lib '../../lib';
    use 5.012;
    use Moose;
    use Moose::Util::TypeConstraints;
    use AnyEvent qw[];
    use AnyEvent::Handle qw[];
    use AnyEvent::HTTP qw[];
    use Ouch;
    use Try::Tiny;
    use XML::Twig;
    use AnyEvent::MSN::Protocol;
    use MIME::Base64 qw[];
    use Scalar::Util qw[];

    # XXX - During dev only
    use Data::Dump;
    sub DEMOLISH { my $s = shift; $s->handle->destroy if $s->_has_handle && $s->handle;$s->_clear_soap_requests }

    # Basic connection info
    has host => (is      => 'ro',
                 writer  => '_set_host',
                 isa     => 'Str',
                 default => 'messenger.hotmail.com'
    );
    has port => (is      => 'ro',
                 writer  => '_set_port',
                 isa     => 'Int',
                 default => 1863
    );

    # Authentication info from user
    has passport => (
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
        required => 1,
        handles  => {
                    username => sub { shift->passport =~ m[^(.+)\@.+$]; $1 },
                    userhost => sub { shift->passport =~ m[^.+\@(.+)$]; $1 }
        }
    );
    has password => (is => 'ro', isa => 'Str', required => 1);

    # User defined extras
    has [qw[friendlyname personalmessage]] =>
        (is => 'ro', isa => 'Str', default => '');

=status
   NLN - Make the client Online (after logging in) and send and receive
   notifications about buddies.
   FLN - Make the client Offline. If the client is already online,
   offline notifications will be sent to users on the RL. No message
   activity is allowed. In this state, the client can only synchronize
   the lists as described above.
   HDN - Make the client Hidden/Invisible. If the client is already
   online, offline notifications will be sent to users on the RL. The
   client will appear as Offline to others but can receive
   online/offline notifications from other users, and can also
   synchronize the lists. Clients cannot receive any instant messages
   in this state.

   All other States are treated as sub-states of NLN (online). The
   other States currently supported are:
   BSY - Busy.
   IDL - Idle.
   BRB - Be Right Back.
   AWY - Away From Computer.
   PHN - On The Phone.
   LUN - Out To Lunch.
=cut

    has status => (is      => 'ro',
                   isa     => enum([qw[NLN FLN BSY IDL BRB AWY PHN LUN]]),
                   default => 'NLN'
    );

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
        default => 'MSNP21',
        lazy    => 1
    );
    map { has $_->[0] => (is => 'ro', isa => 'Str', default => $_->[1]) }
        [qw[product_id PROD0120PW!CCV9@]],
        [qw[product_key C1BX{V4W}Q3*10SM]],
        [qw[locale_id 0x0409]],
        [qw[os_type winnt]],
        [qw[os_ver 6.1.1]],
        [qw[arch i386]],
        [qw[client_name MSNMSGR]],
        [qw[client_version 15.4.3508.1109]],
        [qw[client_string MSNMSGR]];
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
        state $r //= sub {
            join '', map { ('a' .. 'f', 0 .. 9)[rand 15] } 1 .. shift;
        };
        sprintf '{%8s-%4s-%4s-%4s-%12s}', $r->(8), $r->(4), $r->(4), $r->(4),
            $r->(12);
    }
    has location =>
        (is => 'ro', isa => 'Str', default => 'Perl/AnyEvent::MSN');

    # Internals
    has handle => (
        is        => 'ro',
        isa       => 'Object',
        predicate => '_has_handle',
        writer    => '_set_handle',
        clearer   => '_reset_handle',
        handles   => {
            send => sub {
                my $s = shift;
                Scalar::Util::weaken($s);
                $s->handle->push_write('AnyEvent::MSN::Protocol' => @_)
                    if $s->_has_handle;    # XXX - Else mention it...
                }
        }
    );
    has tid => (is      => 'ro',
                isa     => 'Int',
                lazy    => 1,
                clearer => '_reset_tid',
                builder => '_build_tid',
                traits  => ['Counter'],
                handles => {'_inc_tid' => 'inc'}
    );
    sub _build_tid {0}
    after tid => sub { shift->_inc_tid };    # Auto inc
    has ping_timer => (is     => 'ro',
                       isa    => 'ArrayRef',                # AE::timer
                       writer => '_set_ping_timer'
    );

    # Server configuration
    has policies => (
        is      => 'bare',
        isa     => 'HashRef[HashRef]',
        clearer => '_reset_policies',
        writer  => '_set_policies',
        traits  => ['Hash'],
        handles => {_add_policy => 'set',
                    _del_policy => 'delete',
                    policy      => 'get',
                    policies    => 'kv'        # XXX - Really?
        }
    );

    # SOAP
    has SSOsites => (
        is      => 'ro',                   # Single Sign On
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
    has auth_tokens => (is      => 'bare',
                        isa     => 'HashRef[HashRef]',
                        clearer => '_reset_auth_tokens',
                        writer  => '_set_auth_tokens',
                        traits  => ['Hash'],
                        handles => {_add_auth_token => 'set',
                                    _del_auth_token => 'delete',
                                    auth_token      => 'get',
                                    auth_tokens     => 'kv'
                        }
    );
    has contacts => (is      => 'ro',
                     isa     => 'HashRef',
                     clearer => '_reset_contacts',
                     writer  => '_set_contacts',
                     traits  => ['Hash'],
    );

    # Simple callbacks
    has 'on_' . $_ => (
        traits  => ['Code'],
        is      => 'ro',
        isa     => 'CodeRef',
        default => sub {
            sub {1}
        },
        handles => {'trigger_' . $_ => 'execute'},
        )
        for qw[im nudge
        error connect];

    # Auto connect
    sub BUILD {
        my ($s, $p) = @_;
        return if $p->{no_autoconnect};
        $s->connect;
    }

    sub connect {
        my ($s, $r) = @_;
        Scalar::Util::weaken($s);
        $r = " $r" if length $r;
        $s->_set_handle(
            AnyEvent::Handle->new(
                connect    => [$s->host, $s->port],
                on_connect => sub {

                    # Get ready to read data from server
                    $s->handle->push_read(
                        'AnyEvent::MSN::Protocol' => sub {
                            my ($cmd, $tid, @data) = @_;
                            my $method =
                                $s->can('_handle_packet_' . lc($cmd));
                            $method ||= sub {
                                $s->trigger_error('Unhandled command type: ' . $cmd,0);
                            };
                            if ($cmd =~ m[^(?:GCF|MSG|NFY|NOT|SDG|UBX)$])
                            {    # payload types
                                $s->handle->unshift_read(
                                    chunk => $data[-1] // $tid, # GFC:0, MSG:2
                                    sub {
                                        $s->$method(
                                                 $tid, @data,
                                                 $cmd =~ m[GCF]
                                                 ? XML::Simple::XMLin(
                                                     $_[1],
                                                     KeyAttr => [qw[type id]],
                                                     ValueAttr => ['value']
                                                     )
                                                 : $cmd =~ m[(?:MSG|NFY|SDG)]
                                                 ? AnyEvent::MSN::Protocol::__parse_msn_headers($_[1])
                                                 : $_[1]
                                        );
                                    }
                                );
                            }
                            elsif ($cmd =~ m[^\d+$]) {    # Error!
                                $s->trigger_error(AnyEvent::MSN::Protocol::err2str($cmd, @data));
                            }
                            else {
                                $s->$method($tid, @data);
                            }
                        }
                    );

                    # Send version negotiation and basic client info
                    $s->send('VER %d %s CVR0', $s->tid, $s->protocol_version);
                    $s->send('CVR %d %s %s %s %s %s %s %s %s%s',
                             $s->tid,
                             $s->locale_id,
                             $s->os_type,
                             $s->os_ver,
                             $s->arch,
                             $s->client_name,
                             $s->client_version,
                             $s->client_string,
                             $s->passport,
                             ($r // ' 0')
                    );

                    # Schedule first PNG in two mins
                    $s->_set_ping_timer(AE::timer 120,
                                        180, sub { $s->send('PNG') });
                },
                on_connect_error => sub {
                    ...;

                    # XXX - Mention it
                },
                on_drain => sub { },
                on_error => sub {
                    my $h = shift;
                    $h->destroy;
                    return if !$_[0];
                    ouch @_;

                    #...;
                    $s->cleanup($_[1]);
                },
                on_eof => sub {
                    $_[0]->destroy;
                    $s->cleanup('connection closed');
                    ...;
                },
                on_read => sub {
                    warn 'READ!!!!!!!!!!!!!!!!';
                    die shift->rbuf;
                },
                on_write => sub {...}
            )
        );
    }

    # Commands from notification server
    sub _handle_packet_adl {
        my $s = shift;

        # ACK for outgoing ADL
        # $s->send('BLP %d AL', $s->tid);
    }

    sub _handle_packet_chl {    # Official client challenge
        my ($s, $tid, @data) = @_;
        my $data =
            AnyEvent::MSN::Protocol::CreateQRYHash($data[0], $s->product_id,
                                                   $s->product_key);
        $s->send("QRY %d %s %d\r\n%s",
                 $s->tid, $s->product_id, length($data), $data);
    }

    sub _handle_packet_cvr {    # Client version recommendation
        my ($s, $tid, $r, $min_a, $min_b, $url_dl, $url_info) = @_;

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
        $s->send('USR %d SSO I %s', $s->tid, $s->passport);
    }

    sub _handle_packet_gcf {    # Get config
        my ($s, $tid, $len, $r) = @_;
        if ($tid == 0) {        # probably Policy list
            $s->_set_policies($r->{Policy});

            #for (@{$s->policy('SHIELDS')->{config}{block}{regexp}{imtext}}) {
            #    my $regex = MIME::Base64::decode_base64($_);
            #    warn 'Blocking ' . qr[$regex];
            #}
        }
        else {
            ...;
        }
    }

    sub _handle_packet_msg {
        my ($s, $from, $about, $len, $head, $body) = @_;
        given ($head->{'Content-Type'}) {
            when (m[text/x-msmsgsprofile]) {

     #
     # http://msnpiki.msnfanatic.com/index.php/MSNP8:Messages#Profile_Messages
     # My profile message. Expect no body.
            }
            when (m[text/x-msmsgsinitialmdatanotification]) { # Expect no body
            }
            when (m[text/x-msmsgsoimnotification]) {

                # Offline Message Waiting.
                # Expect no body
                # XXX - How do I request it?
            }
            when (m[text/x-msmsgsactivemailnotification]) {
                warn 'You\'ve got mail!/aol'
            }
            when (m[text/x-msmsgsinitialmdatanotification]) {
                warn 'You\'ve got mail!/aol'
            }
            default { shift; ddx \@_; ... }
        }
    }

    sub _handle_packet_qng {
        my ($s, $next) = @_;

        # PONG in reply to our PNG
        $s->_set_ping_timer(AE::timer $next, $next, sub { $s->send('PNG') });
    }

    sub _handle_packet_nfy {
        my ($s, $type, $len, $headers, $data) = @_;
        if ($headers->{From} eq '1:' . $s->passport) {    # Without guid
            my $body = sprintf '<user>' . '<s n="PE">
            <UserTileLocation>0</UserTileLocation><FriendlyName>%s</FriendlyName><PSM>%s</PSM><RUM></RUM><RLT>0</RLT></s>'
                . '<s n="IM"><Status>%s</Status><CurrentMedia></CurrentMedia></s>'
                . '<sep n="PD"><ClientType>1</ClientType><EpName>%s</EpName><Idle>false</Idle><State>%s</State></sep>'
                . '<sep n="PE" epid="%s"><VER>MSNMSGR:15.4.3508.1109</VER><TYP>1</TYP><Capabilities>2952790016:557056</Capabilities></sep>'
                . '<sep n="IM"><Capabilities>2953838624:132096</Capabilities></sep>'
                . '</user>', __html_escape($s->friendlyname),
                __html_escape($s->personalmessage),
                $s->status,
                __html_escape($s->location), $s->status, $s->guid;
            my $out =
                sprintf
                qq[To: 1:%s\r\nRouting: 1.0\r\nFrom: 1:%s;epid=%s\r\n\r\nStream: 1\r\nFlags: ACK\r\nReliability: 1.0\r\n\r\nContent-Length: %d\r\nContent-Type: application/user+xml\r\nPublication: 1.0\r\nUri: /user\r\n\r\n%s],
                $s->passport,
                $s->passport, $s->guid, length($body), $body;
            $s->send("PUT %d %d\r\n%s", $s->tid, length($out), $out);
        }
    }
    sub _handle_packet_not { my $s = shift; ddx \@_; }

    sub _handle_packet_put {
    }

    sub _handle_packet_qry {
        my ($s, $tid) = @_;

        #
        my $token =
            $s->auth_token('contacts.msn.com')
            ->{'wst:RequestedSecurityToken'}{'wsse:BinarySecurityToken'}
            {content};
        $token =~ s/&/&amp;/sg;
        $token =~ s/</&lt;/sg;
        $token =~ s/>/&gt;/sg;
        $token =~ s/"/&quot;/sg;

        # Reply to good challenge. Expect no body.
        $s->soap_request(
            'https://contacts.msn.com:443/abservice/SharingService.asmx',
            {   'content-type' => 'text/xml; charset=utf-8',
                SOAPAction =>
                    '"http://www.msn.com/webservices/AddressBook/FindMembership"'
            },
            sprintf(<<'XML', $token),
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
        <ABApplicationHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <ApplicationId>CFE80F9D-180F-4399-82AB-413F33A1FA11</ApplicationId>
            <IsMigration>false</IsMigration>
            <PartnerScenario>Initial</PartnerScenario>
        </ABApplicationHeader>
        <ABAuthHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <TicketToken>%s</TicketToken>
            <ManagedGroupRequest>false</ManagedGroupRequest>
        </ABAuthHeader>
    </soap:Header>
    <soap:Body>
        <FindMembership xmlns="http://www.msn.com/webservices/AddressBook">
            <ServiceFilter>
                <Types>
                    <Space></Space>
                    <SocialNetwork></SocialNetwork>
                    <Profile></Profile>
                    <Invitation></Invitation>
                    <Messenger></Messenger>
                </Types>
            </ServiceFilter>
        </FindMembership>
    </soap:Body>
</soap:Envelope>
XML
            sub {
                my $contacts = shift;

                # XXX - Do something with these contacts
                #...
            }
        );
        $s->soap_request(
            'https://contacts.msn.com/abservice/abservice.asmx',
            {   'content-type' => 'text/xml; charset=utf-8',
                'SOAPAction' =>
                    '"http://www.msn.com/webservices/AddressBook/ABFindContactsPaged"'
            },
            sprintf(<<'XML', $token),
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header>
        <ABApplicationHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <ApplicationId>3794391A-4816-4BAC-B34B-6EC7FB5046C6</ApplicationId>
            <CacheKey>14r2;Y+G87laDsL3ATl8gJ3C4pPjoMLk5J/tyZUSb1cwTnKI1GlRcRHu65X3d3uqDPuH2pkfTOntU7zMUk9k2dFQwYcre4UXElvfdhjc5KYfm8oZftprkw69TgDuQLTZg4mMoayTnE388tJx4Z8Cx0iLxP/HvZHwsVnrC9RQ6k4aJ8wM=</CacheKey>
            <IsMigration>false</IsMigration>
            <PartnerScenario>Initial</PartnerScenario>
        </ABApplicationHeader>
        <ABAuthHeader xmlns="http://www.msn.com/webservices/AddressBook">
            <TicketToken>%s</TicketToken>
            <ManagedGroupRequest>false</ManagedGroupRequest>
        </ABAuthHeader>
    </soap:Header>
    <soap:Body>
        <ABFindall xmlns="http://www.msn.com/webservices/AddressBook">
            <abID>00000000-0000-0000-0000-000000000000</abID>
        </ABFindall>
        <ABFindContactsPaged xmlns="http://www.msn.com/webservices/AddressBook">
            <extendedContent>AB AllGroups CircleResult</extendedContent>
            <abView>MessengerClient8</abView>
            <filterOptions>
                <DeltasOnly>false</DeltasOnly>
                <ContactFilter>
                    <IncludeShellContacts>true</IncludeShellContacts>
                    <IncludeHiddenContacts>true</IncludeHiddenContacts>
                </ContactFilter>
                <LastChanged>0001-01-01T00:00:00.00-08:00</LastChanged>
            </filterOptions>
            <pageContext>
                <PageSize>1500</PageSize>
                <Direction>Forward</Direction>
            </pageContext>
        </ABFindContactsPaged>
    </soap:Body>
</soap:Envelope>
XML
            sub {
                my $contacts = shift;
                warn 'Got address book...';

                # XXX - Do something with these contacts
                $s->_set_contacts($contacts);
                my $ticket = __html_unescape(
                    $s->contacts->{'soap:Body'}{'ABFindContactsPagedResponse'}
                        {'ABFindContactsPagedResult'}{'CircleResult'}
                        {'CircleTicket'});
                $s->send('USR %d SHA A %s',
                         $s->tid, MIME::Base64::encode_base64($ticket, ''));

                #
                my %contacts;
                {
                    for my $contact (
                             @{  $s->contacts->{'soap:Body'}
                                     {'ABFindContactsPagedResponse'}
                                     {'ABFindContactsPagedResult'}{'Contacts'}
                                     {'Contact'}
                             }
                        )
                    {   my ($user, $domain) = split /\@/,
                            $contact->{'contactInfo'}{'passportName'}, 2;
                        push @{$contacts{$domain}}, $user;
                    }
                }
                my $data = sprintf '<ml>
    %s
</ml>', join '', map {
                    sprintf '<d n="%s">
        %s
    </d>', $_, join '', map {
                        sprintf '<c n="%s" t="1">
            <s l="3" n="IM" />
            <s l="3" n="PE" />
            <s l="3" n="PF" />
        </c>', $_
                        } sort @{$contacts{$_}}
                } sort keys %contacts;
                $s->send("ADL %d %d\r\n%s", $s->tid, length($data), $data);

                #...
            }
        );
    }

    sub _handle_packet_sbs {
        my $s = shift;

        # No one seems to know what this is. Official client ignores it?
    }

    sub _handle_packet_sdg {
        my ($s, $tid, $size, $head, $body) = @_;
        ddx [$head, $body];
        given ($head->{'Message-Type'}) {
            when ('Text') {
                given ($head->{'Service-Channel'}) {
                    $s->trigger_im($head, $body) when 'IM/Online';
                    $s->trigger_im($head, $body) when undef;
                    warn 'Offline Msg!' when 'IM/Offline';
                    default {
                        warn 'unknown IM!!!!!'
                    }
                }
            }
            $s->trigger_nudge($head) when 'Nudge';
            when ('Wink')           { warn 'Wink' }
            when ('CustomEmoticon') { warn 'Custom Emoticon' }
            when ('Control/Typing') { warn 'Typing!' }
            when ('Data') {

=docs

1	 BYTE	HL	 Length of header.
2	 BYTE	OP	 Operation code. 0: None, 2: Ack, 3: Init session.
3	 WORD	ML	 Message length without header length. (but included the header's message length)
4	 DWORD	BaseID	 Initially random (?) To get the next one add the payload length.
TLVs	 BYTE[HL-8]	TLV Data	 TLV list consists of TLV-encoded pairs (type, length, value). A whole TLV list is padded with zeros to fit 4-byte boundary. If header length(HL) greater then 8 TLVs = ReadBytes(HeaderLength - 8) ; else process data packet (D). TLVs: T=0x1(1) L=0xc(12): IPv6 address of sender/receiver. T=0x2(2) L=0x4(4): ACK identifier.
DH	 DHL	Data Header
BYTE DHL: Data header length
BYTE TFCombination: 0x1=First, 0x4=Msn object (display picture, emoticon etc), 0x6=File transfer
WORD PackageNumber: Package number
DWORD SessionID: Session Identifier
BYTE[DHL-8] Data packets TLVs: if (DHL>8) then read bytes(DHL - 8). T=0x1(1) L=0x8(8): Data remaining.
D	 ML-DHL	Data Packet	 SLP messsage or data packet
F	 DWORD	Footer	 The footer.


=cut

                die 'Data'
            }
            when ('Signal/P2P')              { warn 'P2P' }
            when ('Signal/ForceAbchSync')    { }
            when ('Signal/CloseIMWindow')    { }
            when ('Signal/MarkIMWindowRead') { }
            when ('Signal/Turn')             { };
            when ('Signal/AudioMeta')        { }
            when ('Signal/AudioTunnel')      { }
            default                          {...}
        }
    }

    sub _handle_packet_usr {
        my ($s, $tid, $subtype, $_s, $policy, $nonce) = @_;
        if ($subtype eq 'OK') {

            # Sent after we send ADL command. Lastcommand in the logon?
        }
        elsif ($subtype eq 'SSO') {
            my $x      = 1;
            my @tokens = map {
                sprintf <<'TOKEN', $x++, $_->[0], $_->[1] } @{$s->SSOsites};
            <wst:RequestSecurityToken Id="RST%d">
                <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>
                <wsp:AppliesTo>
                    <wsa:EndpointReference>
                        <wsa:Address>%s</wsa:Address>
                    </wsa:EndpointReference>
                </wsp:AppliesTo>
                <wsse:PolicyReference URI="%s"></wsse:PolicyReference>
            </wst:RequestSecurityToken>
TOKEN
            $s->soap_request(
                ($s->passport =~ m[\@msn.com$]i
                 ? 'https://msnia.login.live.com/pp550/RST.srf'
                 : 'https://login.live.com/RST.srf'
                ),
                {},    # headers
                sprintf(<<'XML', $s->password, $s->passport, join '', @tokens),
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2004/04/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
    <Header>
        <wsse:Security>
            <wsse:UsernameToken Id="user">
                <wsse:Password>%s</wsse:Password>
                <wsse:Username>%s</wsse:Username>
            </wsse:UsernameToken>
        </wsse:Security>
        <ps:AuthInfo Id="PPAuthInfo" xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL">
            <ps:Cookies></ps:Cookies>
            <ps:UIVersion>1</ps:UIVersion>
            <ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp>
            <ps:BinaryVersion>4</ps:BinaryVersion>
            <ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDMz</ps:RequestParams>
        </ps:AuthInfo>
    </Header>
    <Body>
        <ps:RequestMultipleSecurityTokens Id="RSTS" xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL">
%s        </ps:RequestMultipleSecurityTokens>
    </Body>
</Envelope>
XML
                sub {
                    my $d = shift;
                    for my $token (
                         @{  $d->{'S:Body'}{
                                 'wst:RequestSecurityTokenResponseCollection'}
                                 {'wst:RequestSecurityTokenResponse'}
                         }
                        )
                    {   $s->_add_auth_token(
                            $token->{'wsp:AppliesTo'}{'wsa:EndpointReference'}
                                {'wsa:Address'},
                            $token
                        );
                    }

                    #
                    if ($policy =~ m[MBI]) {
                        my $token = $s->auth_token('messengerclear.live.com')
                            ;    # or http://Passport.NET/tb
                        my $token_ = __html_escape(
                                 $token->{'wst:RequestedSecurityToken'}
                                     {'wsse:BinarySecurityToken'}{'content'});
                        $s->send('USR %d SSO S %s %s %s',
                                 $s->tid,
                                 $token->{'wst:RequestedSecurityToken'}
                                     {'wsse:BinarySecurityToken'}{'content'},
                                 AnyEvent::MSN::Protocol::SSO(
                                           $nonce,
                                           $token->{'wst:RequestedProofToken'}
                                               {'wst:BinarySecret'}
                                 ),
                                 $s->guid
                        );
                    }
                    elsif ($policy =~ m[^\?]) {
                        ...;
                    }
                }
            );
        }
        elsif ($subtype eq 'OK') {

            # XXX - logged in okay. What now?
        }
        else {
            ...;
        }
    }

    sub _handle_packet_ubx {    # Buddy has changed something
        my ($s, $passport, $len, $payload) = @_;
        my $xml = XML::Twig->new()->parse($payload)->root->simplify
            if $payload;
        if ($len == 0 && $passport eq '1:' . $s->passport) {
        }
        else {
            ddx $xml;
            my ($user) = ($passport =~ m[:(.+)$]);
            $s->_add_contact($user, $xml);
        }
    }

    sub _handle_packet_uux {    # ACK for UUX
    }

    sub _handle_packet_ver {    # Negotiated protocol version
        my ($s, $tid, $r) = @_;
        $s->_set_protocol_version($r);
    }

    sub _handle_packet_xfr {    # Transver to another switchboard
        my $s = shift;
        my ($tid, $type, $addr, $u, $d, $redirect) = @_;
        $s->send('OUT');
        $s->handle->destroy;
        my ($host, $port) = ($addr =~ m[^(.+):(\d+)$]);
        $s->_set_host($host);
        $s->_set_port($port);
        $s->connect($redirect);
    }

    # SOAP client
    has soap_requests => (isa =>'HashRef[AnyEvent::Util::guard]',traits=>['Hash'], handles =>{_add_soap_request=>'set', _del_soap_request => 'delete', _clear_soap_requests => 'clear' } )
;    sub soap_request {
        my ($s, $uri, $headers, $content, $cb) = @_;
        my %headers = ('user-agent' => 'MSNPM 1.0',
                       'content-type' =>
                           'application/soap+xml; charset=utf-8; action=""',
                       'Expect'     => '100-continue',
                       'connection' => 'Keep-Alive'
        );
        @headers{keys %$headers} = values %$headers;

        $s->_add_soap_request($uri,AnyEvent::HTTP::http_request(
            POST       => $uri,
            headers    => \%headers,
            timeout    => 15,
            persistent => 1,
            body       => $content,
            sub {
                my ($body, $hdr) = @_;
                state $xml_twig //= XML::Twig->new();
                $xml_twig->parse($body) if $body;    # build it
                my $xml;
                try {
                    $xml = $xml_twig->simplify;
                }
                catch {
                    $s->trigger_error(qq[During SOAP request $_], 1);                  $xml = {};
                };
                        $s->_del_soap_request($uri );

                return $cb->($xml)
                    if $hdr->{Status} =~ /^2/ && !defined $xml->{'S:Fault'};
                ddx $hdr;
                $s->trigger_error(
                    $xml->{'S:Fault'}{'soap:Reason'}{'soap:Text'}{'content'}
                        // $xml->{'S:Fault'}{'faultstring'} // $hdr->{Reason},
                    1
                );

            }
        )
          );
     }

    # Methods exposed publicly
    sub disconnect {    # cleanly disconnect from switchboard
        my $s = shift;
        $s->send('OUT');
        $s->handle->on_drain(
            sub {
                $s->handle->destroy;
            }
        );
    }

    sub im {
        my ($s, $to, $msg, $format) = @_;
        $to = '1:' . $to if $to !~ m[^\d+:];
        $format //= 'FN=Segoe%20UI; EF=; CO=0; CS=1; PF=0';

        # FN: Font name (url safe)
        # EF: String containing...
        # - B for Bold
        # - U for Underline
        # - I for Italics
        #　- S for Strikethrough
        # CO: Color (hex without #)
        my $data =
            sprintf
            qq[Routing: 1.0\r\nTo: %s\r\nFrom: 1:%s;epid=%s\r\n\r\nReliability: 1.0\r\n\r\nMessaging: 2.0\r\nMessage-Type: Text\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: %d\r\nX-MMS-IM-Format: %s\r\n\r\n%s],
            $to, $s->passport, $s->guid, length($msg), $format, $msg;
        $s->send(qq'SDG 0 %d\r\n%s', length($data), $data);
    }

    sub nudge {
        my ($s, $to) = @_;
        $to = '1:' . $to if $to !~ m[^\d+:];
        my $data =
            sprintf
            qq[Routing: 1.0\r\nTo: %s\r\nFrom: 1:%s;epid=%s\r\n\r\nReliability: 1.0\r\n\r\nMessaging: 2.0\r\nMessage-Type: Nudge\r\nService-Channel: IM/Online\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Length: 0\r\n\r\n],
            $to, $s->passport, $s->guid;
        $s->send(qq'SDG 0 %d\r\n%s', length($data), $data);
    }

    # Non-OOP utility functions
    sub __html_escape {
        my $x = shift;
        $x =~ s[&][&amp;]sg;
        $x =~ s[<][&lt;]sg;
        $x =~ s[>][&gt;]sg;
        $x =~ s["][&quot;]sg;
        $x;
    }

    sub __html_unescape {
        my $x = shift;
        $x =~ s[&lt;][<]sg;
        $x =~ s[&gt;][>]sg;
        $x =~ s[&quot;]["]sg;
        $x =~ s[&amp;][&]sg;
        $x;
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


=head1 Methods




=head1 Notes

This is where random stuff will go. The sorts of things which may make life
somewhat easier for you but are easily skipped.

=head2 IM/Chat Message Formatting

The L<im|/im> method's third parameter '

=head1 TODO

These are things I have plans to do with L<AnyEvent::MSN> but haven't found
the time to complete them. If you'd like to help or have a suggestion for new
feature, see the project pages on
L<GitHub|http://github.com/sanko/anyevent-msn>.

=over

=item P2P Transfers

MSNP supports simple file transfers, handwritten IMs, voice chat, and even
webcam sessions through the P2P protocol.

=item Group Chat

MSNP21 redefinied the switchboard concept including how group chat sessions
are initiated and handled.

=item Internal State Cleanup

Things like the address book are very difficult to use because (for now) I
simply store the parsed XML Microsoft sends me.

=back

=head1 See Also

=over

=item L<Net::MSN|Net::MSN>

=item L<MSN::PersonalMessage|MSN::PersonalMessage>

=item L<POE::Component::Client::MSN|POE::Component::Client::MSN>

=item L<Net::Msmgr::Session|Net::Msmgr::Session>

=back

=head1 Legal... etc.



=cut
