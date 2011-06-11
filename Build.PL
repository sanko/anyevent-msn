use Module::Build;
Module::Build->new(module_name => 'AnyEvent::MSN',
                   license     => 'artistic_2',
                   requires    => {
                                perl              => '5.012',
                                AnyEvent          => '5.31',
                                'AnyEvent::HTTP'  => '2.1',
                                'MIME::Base64'    => '3.13',
                                'Moose'           => '2.0002',
                                'Try::Tiny'       => '0.09',
                                'XML::Twig'       => '3.38',
                                'Digest::HMAC'    => '1.02',
                                'Digest::SHA'     => '5.61',
                                'Digest::MD5'     => '2.51',
                                'Crypt::CBC'      => '2.30',
                                'Crypt::DES'      => '2.05',
                                'Crypt::DES_EDE3' => '0.01'
                   },
                   configure_requires => {'Module::Build' => 0.38}
)->create_build_script;
