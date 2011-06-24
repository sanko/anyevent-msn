#!/usr/bin/perl -I../lib
use AnyEvent;
use AnyEvent::MSN;
use 5.012;
$|++;
my ($user, $pass) = @ARGV;    # XXX - Better to use a GetOpt-like module
my $cv = AnyEvent->condvar;
my $msn = AnyEvent::MSN->new(
    passport => $user,  # XXX - I may change the name of this arg before pause
    password => $pass,

    # Extra user info
    status          => 'AWY',
    friendlyname    => 'Just another MSN hacker,',
    personalmessage => 'This can\'t be life!',

    # Basic events
    on_connect => sub { warn 'Connected as ' . shift->passport },
    on_im      => sub { # simple echo bot
        my ($msn, $head, $body) = @_;
        $msn->send_messsage($head->{From}, $body);
    },
    on_nudge => sub {
        my ($msn, $head) = @_;
        warn $head->{From} . ' just nudged us';
        $msn->nudge($head->{From});
    },
    on_error => sub {
        my ($msn, $msg) = @_;
        warn 'Error: '. $msg;
      },

    on_fatal_error => sub {
        my ($msn, $msg, $fatal) = @_;
        warn sprintf 'Fatal error: ' . $msg;
        $msn->connected ? $msn->connect : $cv->send    # auto-reconnect
    }
);
$cv->recv;

=pod

=head1 Author

Sanko Robinson <sanko@cpan.org> - http://sankorobinson.com/

CPAN ID: SANKO

=head1 License and Legal

Copyright (C) 2011 by Sanko Robinson <sanko@cpan.org>

This program is free software; you can redistribute it and/or modify it under
the terms of
L<The Artistic License 2.0|http://www.perlfoundation.org/artistic_license_2_0>.
See the F<LICENSE> file included with this distribution or
L<notes on the Artistic License 2.0|http://www.perlfoundation.org/artistic_2_0_notes>
for clarification.

When separated from the distribution, all original POD documentation is
covered by the
L<Creative Commons Attribution-Share Alike 3.0 License|http://creativecommons.org/licenses/by-sa/3.0/us/legalcode>.
See the
L<clarification of the CCA-SA3.0|http://creativecommons.org/licenses/by-sa/3.0/us/>.

Neither this module nor the L<Author|/Author> is affiliated with Microsoft.

=cut
