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
    passport => $user, # XXX - I may change the name of this arg before pause
    password => $pass,

    # Extra user info
    status          => 'AWY',
    friendlyname    => 'Just another MSN hacker,',
    personalmessage => 'This can\'t be life!',

    # Basic events
    on_im => sub {            # Simple Ping/Pong bot
        my ($head, $body) = @_;
        printf qq'%-40s> %s\n', $head->{From}, $body;
        $msn->im($head->{From}, 'Pong!') if $body eq 'Ping?';
    },
    on_nudge => sub {
        my $head = shift;
        warn $head->{From} . ' just nudged us';
        $msn->nudge($head->{From});
    },
);
AnyEvent->condvar->recv;
