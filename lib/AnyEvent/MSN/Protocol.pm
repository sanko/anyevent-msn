package AnyEvent::MSN::Protocol 0.001;
{
    use strict;
    use AnyEvent;
    use Data::Dump;
    use Ouch;
    use MIME::Base64 qw[];
    use Digest::HMAC qw[hmac];
    use Digest::SHA qw[];
    use Crypt::CBC qw[];
    use XML::Simple;

    sub anyevent_read_type {    # Non-traditional args
        my ($handle, $s) = @_;
        sub {
            return if !length $handle->{rbuf};
            $handle->{rbuf} =~ s[^([^\015\012]*)(\015?\012)][] or return;
            my $line = $1;
            my ($cmd, $tid, @data) = split qr[\s+], $line;
            my $method = $s->can('_handle_packet_' . lc($cmd));
            $method ||= sub { ouch 110, 'Unhandled command type: ' . $cmd };
            if ($cmd =~ m[^(?:GCF|MSG)$]) {    # payload types
                warn '>> ' . $line . ' [...]';
                $handle->unshift_read(
                    chunk => $data[-1], # GFC:0, MSG:2
                    sub {$s->$method($tid, @data,
                                    $cmd =~ m[GCF] ?
                                    XML::Simple::XMLin(
                                                     $_[1],
                                                     KeyAttr => [qw[type id]],
                                                     ValueAttr => ['value']
                                    ): $_[1]
                        );
                    }
                );
            }
            else {
                warn '>> ' . $line;
                $s->$method($tid, @data);
            }
            $handle->push_read(__PACKAGE__, $s);    # Re-queue
            return 1                                # But remove this one
        }
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
