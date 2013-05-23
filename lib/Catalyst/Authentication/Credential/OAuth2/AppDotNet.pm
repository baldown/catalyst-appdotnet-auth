package Catalyst::Authentication::Credential::OAuth2::AppDotNet;

use 5.006;
use strict;
use warnings FATAL => 'all';

use base qw(Catalyst::Authentication::Credential::OAuth2);

use HTTP::Request;

=head1 NAME

Catalyst::Authentication::Credential::OAuth2::AppDotNet - OAuth2 authentication
for App.net server-side applications.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.05';


=head1 SYNOPSIS

This module provides access to App.net authentication and authorization APIs via OAuth2.  Information about the OAuth2 authentication process is available under the App.net API documentation (http://developers.app.net/) at http://developers.app.net/docs/authentication/flows/web/.

=head1 EXAMPLE

Below is the set of things you need to do once you have an App.net Developer account, and have generated an app client id and secret.

=head2 Package Config

Configure your app's authentication options, like:

__PACKAGE__->config(
  'Plugin::Authentication' => { 
    default => {
     credential => { 
        class => 'OAuth2::AppDotNet', 
        grant_uri => 'https://account.app.net/oauth/authenticate', 
        token_uri => 'https://account.app.net/oauth/access_token', 
        client_id => 'your id token here',
        client_secret => 'your secret',
      }, 
      store => { class => 'Null' } 
    }
  });

=head2 Auth Controller Setup

Create an auth controller, an in it place a login action similar to the following:

sub login :Path {
    my ( $self, $c ) = @_;

    my %auth_args = (
        scope => 'basic write_post files',
    );

    $auth_args{state} = $c->req->referer if $c->req->referer;

    my $user = $c->authenticate(\%auth_args);

    $c->detach unless $user;

    # Do something to process the user blob returned, which is a hash like below
    
    if ($c->req->param('state')) {
        $c->response->redirect($c->req->param('state'));
    } else {
        $c->response->redirect('/');
    }
}

=head2 Handle the User Data

The hash returned by authenticate() will look like:

{
token => "AQAAAAAABXbK1aOr_OIg5f9-IaxEj9VZU8xLXChojDN6ZrWRHRPq0Q7ujq89Z4Mg57zvkshY2PtWPrEpME1mfEjG0vPBr28lQ",
username => "baldown",
avatar_image => {
  url => "https://d2rfichhc2fb9n.cloudfront.net/image/5/wiEDnUBtrtjzNqPMq6j6hUJ5mjN7InMiOiJzMyIsImIiOiJhZG4tdXNlci1hc3NldHMiLCJrIjoiYXNzZXRzL3VzZXIvZjYvMzcvMjAvZjYzNzIwMDAwMDAwMDAwMC5qcGciLCJvIjoiIn0",
  width => 200,
  is_default => "false",
  height => 200,
},
description => {
  text => "Man of God, husband to a wonderful wife, father of 3 amazing kids, K-State alum. Telecommuter. Perl dev, packet and security nerd living in Kansas City.",
  html => "<span itemscope=\"https://app.net/schemas/Post\">Man of God, husband to a wonderful wife, father of 3 amazing kids, K-State alum. Telecommuter. Perl dev, packet and security nerd living in Kansas City.</span>",
  entities => {
    mentions => [],
    hashtags => [],
    links => []
  }
},
locale => "en_US",
created_at => "2012-11-30T20:21:52Z",
id => "28848",
verified_domain => "standingaroundcoding.com",
cover_image => {
  url => "https://d2rfichhc2fb9n.cloudfront.net/image/5/exqPUJyQj5JSgB5BhbxpZcWeC8B7InMiOiJzMyIsImIiOiJhZG4tdXNlci1hc3NldHMiLCJrIjoiYXNzZXRzL3VzZXIvY2UvMjYvMjAvY2UyNjIwMDAwMDAwMDAwMC5qcGciLCJvIjoiIn0",
  width => 3264,
  is_default => "false",
  height => 2448
},
timezone => "America/Los_Angeles",
counts => {
  following => 57,
  followers => 47,
  posts => 326,
  stars => 19
}
type => "human",
canonical_url => "https://alpha.app.net/baldown",
name => "Josh Ballard"
}

=head2 Forcing Authentication

Then, whenever the user needs to be authenticated, $c->request->redirect to '/auth/login'.  The login function will keep the page you refered from, and redirect back to it when authentication via App.net has completed.

=head1 SUBROUTINES/METHODS

There are many subroutines under the hood of this module; some inherited from Catalyst::Authentication::Credential::OAuth2, and some local.  But you will never really tocuh any of them.  All you will ever need is $c->authenticate() and some options.

=head2 $c->authenticate({options})

For our case of authenticate, we take 2 options inside of a hashref, state and scope.

=head3 Scope

The scope is a space delimited string of thr types of privileges we are requesting to the authenticating user's account.  This can be things like basic, follow, messages, post, etc.

=head3 State

State is a bit of information we can pass into the authentication process that comes back to us in the end.  In the example above, we use state to pass in the URL we came to authentication from ao that we may redirect back to it in the end.

=cut

sub authenticate {
  my ( $self, $ctx, $realm, $auth_info ) = @_;
  my $callback_uri = $self->_build_callback_uri($ctx);

  unless ( defined( my $code = $ctx->request->params->{code} ) ) {
    my $auth_url = $self->extend_permissions( $callback_uri, $auth_info
 );
    $ctx->response->redirect($auth_url);

    return;
  } else {
    my $token =
      $self->request_access_token( $callback_uri, $code, $auth_info );
    die 'Error validating verification code' unless $token;
    my $userpath = $token->{token}->{user};
    return $realm->find_user( { token => $token->{access_token}, map { $_ => $userpath->{$_} } keys %$userpath }, $ctx);
  }
}

sub extend_permissions {
  my ( $self, $callback_uri, $auth_info ) = @_;
  my $uri   = URI->new( $self->grant_uri );
  my $query = {
    response_type => 'code',
    client_id     => $self->client_id,
    redirect_uri  => $callback_uri
  };
  $query->{scope} = $auth_info->{scope} if exists $auth_info->{scope};
  $query->{state} = $auth_info->{state} if exists $auth_info->{state};
  $uri->query_form($query);
  return $uri;
}


sub request_access_token {
  my ( $self, $callback_uri, $code, $auth_info ) = @_;
  my $j = JSON::Any->new;
  my $request = HTTP::Request->new(POST => $self->token_uri);
  $request->header('Content-Type' => 'application/x-www-form-urlencoded');
  my $query = {
    client_id    => $self->client_id,
    client_secret => $self->client_secret,
    redirect_uri => $callback_uri,
    code         => $code,
    grant_type   => 'authorization_code'
  };
  $query->{state} = $auth_info->{state} if exists $auth_info->{state};
  my $content = join('&', map { sprintf('%s=%s', $_, $query->{$_}) } keys %$query);
  $request->content($content);
  $request->header('Content-Length' => length($content));
  
  my $response = $self->ua->request($request);
  return unless $response->is_success;
  return $j->jsonToObj( $response->decoded_content );
}

=head1 AUTHOR

Josh Ballard, C<< <josh at oofle.com> >>

=head1 ACKNOWLEDGEMENTS

Florian Ragwitz for creating Catalyst::Authentication::Credential::Facebook::OAuth2
and Eden Cardim for adapting that to a generalized OAuth2 module.

=head1 LICENSE AND COPYRIGHT

Copyright 2013 Josh Ballard, Standing::Around::Coding.

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut

1; # End of Catalyst::Authentication::Credential::OAuth2::AppDotNet
