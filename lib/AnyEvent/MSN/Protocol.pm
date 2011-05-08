package AnyEvent::MSN::Protocol 0.001;
{
    use AnyEvent;
    use Data::Dump;
    use Ouch;
    use MIME::Base64 qw[];
    use Digest::HMAC qw[hmac];
    use Digest::SHA qw[];
    use Crypt::CBC qw[];
    use XML::Simple;

    sub anyevent_read_type {
        my ($handle, $cb) = @_;
        return sub {
            $handle->push_read(
                line => sub {
                    my $line = $_[1];
                    warn '>> ' . $line;
                    my ($cmd, $tid, $data) = split ' ', $line, 3;
                    if ($cmd eq 'CHL') {    # CHaLlenge
                        $cb->($tid, $data);
                    }
                    elsif ($cmd =~ m[^CV[QR]$]) {    # Version info reply
                            # Actually CVR but official client is okay w/ CVQ
                        $cb->($tid, split ' ', $data, 5);
                    }
                    elsif ($cmd eq 'GCF') {    # Get ConFig
                        $handle->unshift_read(
                            chunk => $data,
                            sub {
                                shift;
                                $cb->($tid,
                                      XML::Simple::XMLin(
                                                     shift,
                                                     KeyAttr => [qw[type id]],
                                                     ValueAttr => ['value']
                                      )
                                );
                            }
                        );
                    }
                    elsif ($cmd eq 'USR') {
                        $cb->(split ' ', $data);    # XXX - Eh?
                    }
                    elsif ($cmd eq 'VER') {    # protocol VERsion negotiation
                        if ($data eq '0') {
                            my $err = 'Failed to negotiate protocol version';
                            ouch $data,
                                'Failed to negotiate protocol version';
                            return 1;
                        }
                        my (@prot) = split ' ', $data;
                        $cb->($tid, @prot ? @prot : undef);    # XXX - Eh?
                    }
                    elsif ($cmd eq 'XFR') {                    # Transfer
                        $cb->($tid, split ' ', $data);
                    }
                    else {
                        ouch 0, 'Unhandled command: ' . $line;
                        return 1;
                    }

=cut

            my $cmd = substr($line, 0, 1);
            my $value = substr($line, 1);
            if ($cmd eq '*') {
                # Multi-bulk reply
                my $remaining = $value;
                if ($remaining == 0) {
                    $cb->([]);
                } elsif ($remaining == -1) {
                    $cb->(undef);
                } else {
                    my $results = [];
                    $handle->unshift_read(sub {
                        my $need_more_data = 0;
                        do {
                            if ($handle->{rbuf} =~ /^(\$(-?\d+)\015\012)/) {
                                my ($match, $vallen) = ($1, $2);
                                if ($vallen == -1) {
                                    # Delete the bulk header.
                                    substr($handle->{rbuf}, 0, length($match), '');
                                    push @$results, undef;
                                    unless (--$remaining) {
                                        $cb->($results);
                                        return 1;
                                    }
                                } elsif (length $handle->{rbuf} >= (length($match) + $vallen + 2)) {
                                    # OK, we have enough in our buffer.
                                    # Delete the bulk header.
                                    substr($handle->{rbuf}, 0, length($match), '');
                                    my $value = substr($handle->{rbuf}, 0, $vallen, '');
                                    $value = $handle->{encoding}->decode($value)
                                        if $handle->{encoding} && $vallen;
                                    push @$results, $value;
                                    # Delete trailing data characters.
                                    substr($handle->{rbuf}, 0, 2, '');
                                    unless (--$remaining) {
                                        $cb->($results);
                                        return 1;
                                    }
                                } else {
                                    $need_more_data = 1;
                                }
                            } elsif ($handle->{rbuf} =~ s/^([\+\-:])([^\015\012]*)\015\012//) {
                                my ($cmd, $value) = ($1, $2);
                                if ($cmd eq '+' || $cmd eq ':') {
                                    push @$results, $value;
                                } elsif ($cmd eq '-') {
                                    # Embedded error; this seems possible only in EXEC answer,
                                    #  so include error in results; don't abort parsing
                                    push @$results, bless \$value, 'AnyEvent::Redis::Error';
                                }
                                unless (--$remaining) {
                                    $cb->($results);
                                    return 1;
                                }
                            } elsif (substr($handle->{rbuf}, 0, 1) eq '*') {
                                # Oh, how fun!  A nested bulk reply.
                                my $reader; $reader = sub {
                                    $handle->unshift_read("AnyEvent::Redis::Protocol" => sub {
                                            push @$results, $_[0];
                                            if (--$remaining) {
                                                $reader->();
                                            } else {
                                                undef $reader;
                                                $cb->($results);
                                            }
                                    });
                                };
                                $reader->();
                                return 1;
                            } else {
                                # Nothing matched - read more...
                                $need_more_data = 1;
                            }
                        } until $need_more_data;
                        return; # get more data
                    });
                }
            } elsif ($cmd eq '+' || $cmd eq ':') {
                # Single line/integer reply
                $cb->($value);
            } elsif ($cmd eq '-') {
                # Single-line error reply
                $cb->($value, 1);
            } elsif ($cmd eq '$') {
                # Bulk reply
                my $length = $value;
                if ($length == -1) {
                    $cb->(undef);
                } else {
                    # We need to read 2 bytes more than the length (stupid
                    # CRLF framing).  Then we need to discard them.
                    $handle->unshift_read(chunk => $length + 2, sub {
                        my $data = $_[1];
                        my $value = substr($data, 0, $length);
                        $value = $handle->{encoding}->decode($value)
                            if $handle->{encoding} && $length;
                        $cb->($value);
                    });
                }
            }

=cut
                    return 1;
                }
            );
            return 1;
        };
    }

    sub anyevent_write_type {    # XXX - Currently... not... right.
        my ($handle, @args) = @_;
        my $out = sprintf shift(@args), grep {defined} @args;
        warn '<< ' . $out;
        return "$out\015\012";
    }

    sub derive_key {
        my ($key, $magic) = @_;
        $magic = 'WS-SecureConversationSESSION KEY ' . $magic;
        my $hash1 = hmac($magic,          $key, \&Digest::SHA::sha1);
        my $hash2 = hmac($hash1 . $magic, $key, \&Digest::SHA::sha1);
        my $hash3 = hmac($hash1,          $key, \&Digest::SHA::sha1);
        my $hash4 = hmac($hash3 . $magic, $key, \&Digest::SHA::sha1);
        my $derived_key = $hash2;
        $derived_key .= substr($hash4, 0, 4);
        return $derived_key;
    }

    sub SSO {
        my ($nonce, $secret, $iv) = @_;

        # 1. Base64 decode binary secret
        my $key1 = MIME::Base64::decode_base64($secret);

        # 2a. key2 and key3
        my $key2 = derive_key($key1, 'HASH');
        my $key3 = derive_key($key1, 'ENCRYPTION');

        # 3. hash
        my $hash = Digest::HMAC::hmac($nonce, $key2, \&Digest::SHA::sha1);

        # 4. Pad nonce with 8 bytes of \08
        my $p_nonce = $nonce . (chr(8) x 8);

        # 5. Create 8 bytes of random data as iv
        $iv //= Crypt::CBC->random_bytes(8);

        # 6. TripleDES CBC encryption
        my $encrypted_data =
            Crypt::CBC->new(-literal_key => 1,
                            -key         => $key3,
                            -iv          => $iv,
                            -header      => 'none',
                            -cipher      => 'Crypt::DES_EDE3'
            )->encrypt($p_nonce);

        # 7. Fill in the struct
        my $struct = pack 'I7 A8 A20 A72', 28, 1, 0x6603, 0x8004, 8, 20, 72,
            $iv,
            $hash, $encrypted_data;

        # 8 Base64 encode struct
        MIME::Base64::encode_base64($struct, '');
    }
}
1;

=pod

=head1 NAME

AnyEvent::MSN::Protocol - Meh.

=cut
