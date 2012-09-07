package CatalystX::OAuth2::Store::CouchDB;
use Moose;
use Moose::Util::TypeConstraints;
#use Catalyst::Plugin::CouchDB;
use Store::CouchDB;

# ABSTRACT: An interface to a CouchDB OAuth2 store

with 'CatalystX::OAuth2::Store';

has _couch => (
    isa        => 'Store::CouchDB',
    is         => 'ro',
    #lazy_build => 1,
    default    => sub { Store::CouchDB->new({db => 'iwmn_oauth'}) });
has endpoint_field   => (isa => 'Str', is => 'ro', default => 'endpoint');
has refresh_relation => (isa => 'Str', is => 'ro', default => 'refresh_tokens');
has token_relation   => (isa => 'Str', is => 'ro', default => 'tokens');
has code_relation    => (isa => 'Str', is => 'ro', default => 'codes');
has code_activation_field => (isa => 'Str', is => 'ro', default => 'is_active');

sub find_client {
    my ($self, $id) = @_;
    my $docs = $self->_couch->get_view({
            view => 'oauth/by_access_id',
            opts => { key => $id } });
    return $docs->{$id} || undef;
}

sub client_endpoint {
    my ($self, $id) = @_;
    my $client = $self->find_client($id)
        or return;
    return $client->{endpoint} || undef;
}

# D
sub _code_rs {
    my ($self, $id) = @_;
    return $self->_client_model->related_resultset($self->code_relation)
        unless defined($id);
    my $client = $self->find_client($id)
        or return;
    return $client->{code_relation};
}

# *
sub create_client_code {
    my ($self, $id) = @_;
    $self->_code_rs($id)->create({});
}

sub find_client_code {
    my ($self, $code) = @_;

    my $docs = $self->_couch->get_view({
            view => 'oauth/code_by_id',
            opts => { key => $code } });
    return $docs->{$code} || undef;
}

sub activate_client_code {
    my ($self, $id, $code) = @_;
    my $code_doc = $self->find_client_code($code)
        or return;
    $code_doc->{active} = 1;
    return $self->_couch->put_doc({doc => $code_doc, name => $code_doc->{_id}});
}

sub deactivate_client_code {
    my ($self, $id, $code) = @_;
    my $code_doc = $self->find_client_code($code)
        or return;
    delete $code_doc->{active};
    return $self->_couch->put_doc({doc => $code_doc, name => $code_doc->{_id}});
}

sub client_code_is_active {
    my ($self, $code) = @_;
    my $client = $self->find_client_code($code)
        or return;
    return exists $client->{active};
}

sub create_access_token {
    my ($self, $code, $refresh_token) = @_;
    my $code_doc = $self->find_client_code($code)
        or return;
    my $token = {
        code => $code,
        type => 'bearer',
        owner => $code_doc->{owner},
        expires_in => time + 3600,
    };
    $token->{refresh_token} = $refresh_token
        if $refresh_token;
    return $self->_couch->put_doc({doc => $token});
}

sub create_access_token_from_refresh {
    my ($self, $refresh) = @_;
    my $docs = $self->_couch->get_view({
            view => 'oauth/refresh_by_id',
            opts => { key => $refresh } });
    return unless exists $docs->{$refresh};
    return $self->create_access_token($docs->{$refresh}->{code});
}

sub find_code_from_refresh {
    my ($self, $refresh) = @_;
    my $docs = $self->_couch->get_view({
            view => 'oauth/refresh_by_id',
            opts => { key => $refresh } });
    return unless exists $docs->{$refresh};
    return $docs->{$refresh}->{code};
}

sub verify_client_secret {
    my ($self, $client_id, $access_secret) = @_;
    my $client = $self->find_client($client_id);
    return $client->{client_secret} eq $access_secret;
}

sub verify_client_token {
    my ($self, $access_token) = @_;
    
    return 0 unless $access_token;
    my $docs = $self->_couch->get_view({
            view => 'oauth/token_by_id',
            opts => { key => $access_token } });
    return $docs->{$access_token} || 0;
}

1;
