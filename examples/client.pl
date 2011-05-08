#!/usr/bin/perl -I../lib
use strict;
use warnings;
use AnyEvent;
use AnyEvent::MSN;
$|++;
AnyEvent::MSN->new(username => 'msn@hotmail.com',
                   password => 'password'
)->connect->recv;
