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

    # This piece of code was written by Siebe Tolsma (Copyright 2004, 2005).
    sub CreateQRYHash {
        use Math::BigInt;    # Only locally
        my ($chldata, $prodid, $prodkey) = @_;

 # Create an MD5 hash out of the given data, then form 32 bit integers from it
        my @md5hash =
            unpack("a16a16", Digest::MD5::md5_hex("$chldata$prodkey"));
        my @md5parts = MD5HashToInt("$md5hash[0]$md5hash[1]");

# Then create a valid productid string, divisable by 8, then form 32 bit integers from it
        my @chlprodid = CHLProdToInt(
             "$chldata$prodid" . ("0" x (8 - length("$chldata$prodid") % 8)));

        # Create the key we need to XOR
        my $key = KeyFromInt(@md5parts, @chlprodid);

        # Take the MD5 hash and split it in two parts and XOR them
        my $low =
            substr(Math::BigInt->new("0x$md5hash[0]")->bxor($key)->as_hex(),
                   2);
        my $high =
            substr(Math::BigInt->new("0x$md5hash[1]")->bxor($key)->as_hex(),
                   2);

        # Return the string, make sure both parts are padded though if needed
        return
              ('0' x (16 - length($low)))
            . $low
            . ('0' x (16 - length($high)))
            . $high;
    }

    sub KeyFromInt {

        # We take it the first 4 integers are from the MD5 Hash
        my @md5 = splice(@_, 0, 4);
        my @chlprod = @_;

        # Create a new series of numbers
        my $key_temp = Math::BigInt->new(0);
        my $key_high = Math::BigInt->new(0);
        my $key_low  = Math::BigInt->new(0);

       # Then loop on the entries in the second array we got in the parameters
        for (my $i = 0; $i < scalar(@chlprod); $i += 2) {

# Make $key_temp zero again and perform calculation as described in the documents
            $key_temp->bzero()->badd($chlprod[$i])->bmul(0x0E79A9C1)
                ->bmod(0x7FFFFFFF)->badd($key_high);
            $key_temp->bmul($md5[0])->badd($md5[1])->bmod(0x7FFFFFFF);

            # So, when that is done, work on the $key_high value :)
            $key_high->bzero()->badd($chlprod[$i + 1])->badd($key_temp)
                ->bmod(0x7FFFFFFF);
            $key_high->bmul($md5[2])->badd($md5[3])->bmod(0x7FFFFFFF);

            # And add the two parts to the low value of the key
            $key_low->badd($key_temp)->badd($key_high);
        }

        # At the end of the loop we should add the dwords and modulo again
        $key_high->badd($md5[1])->bmod(0x7FFFFFFF);
        $key_low->badd($md5[3])->bmod(0x7FFFFFFF);

# Byteswap the keys, left shift (32) the high value and then add the low value
        $key_low  = unpack("I*", reverse(pack("I*", $key_low)));
        $key_high = unpack("I*", reverse(pack("I*", $key_high)));
        return $key_temp->bzero()->badd($key_high)->blsft(32)->badd($key_low);
    }

# Takes an CHLData + ProdID + Padded string and chops it in 4 bytes. Then converts to 32 bit integers
    sub CHLProdToInt {
        return
            map { unpack("I*", $_) }
            unpack(("a4" x (length($_[0]) / 4)), $_[0]);
    }

# Takes an MD5 string and chops it in 4. Then "decodes" the HEX and converts to 32 bit integers. After that it ANDs
    sub MD5HashToInt {
        return
            map { unpack("I*", pack("H*", $_)) & 0x7FFFFFFF }
            unpack(("a8" x 4), $_[0]);
    }


    }
}
1;

=pod

=head1 NAME

AnyEvent::MSN::Protocol - Meh.

=cut
