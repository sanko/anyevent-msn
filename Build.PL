use Module::Build;
Module::Build->new(
    module_name => 'AnyEvent::MSN',
    license     => 'artistic_2',
    requires    => {
                 perl              => '5.012',
                 AnyEvent          => '5.31',
                 'AnyEvent::HTTP'  => '2.1',
                 'Crypt::CBC'      => '2.30',
                 'Crypt::DES'      => '2.05',
                 'Crypt::DES_EDE3' => '0.01',
                 'Data::Dump'      => '1.19',      # Temporary.
                 'Digest::HMAC'    => '1.02',
                 'Digest::SHA'     => '5.61',
                 'MIME::Base64'    => '3.13',
                 'Moose'           => '2.0002',
                 'Ouch'            => '0.0401',    # Temporary.
                 'XML::Simple'     => '2.18'
    },
    configure_requires => {'Module::Build' => 0.38}
)->create_build_script;
