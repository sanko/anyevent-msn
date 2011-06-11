#!/usr/bin/perl -I../lib
use strict;
use warnings;
use AnyEvent;
use AnyEvent::MSN;
use 5.012;
$|++;
my ($user, $pass) = @ARGV;    # XXX - Better to use a GetOpt-like module
my $msn;
$msn = AnyEvent::MSN->new(
    passport => $user,  # XXX - I may change the name of this arg before pause
    password => $pass,

    # Extra user info
    status          => 'AWY',
    friendlyname    => 'Just another MSN hacker,',
    personalmessage => 'This can\'t be life!',

    # Basic events
    on_connect => sub { warn 'Connected as ' . shift->passport },
    on_im      => sub {
        my ($msn, $head, $body) = @_;
        $msn->im($head->{From}, $body);
    },
    on_nudge => sub {
        my ($msn, $head) = @_;
        warn $head->{From} . ' just nudged us';
        $msn->nudge($head->{From});
        $msn->add_buddy('msn@penilecolada.com');
        $msn->set_status('NLN');
    },
    on_error => sub {
        my ($msn, $msg, $fatal) = @_;
        warn ucfirst sprintf '%serror: %s', ($fatal ? 'fatal ' : ''), $msg;
        $msn = () if $fatal;
    }
);
AnyEvent->condvar->recv;
