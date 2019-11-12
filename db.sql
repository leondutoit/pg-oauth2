
/*

OAuth2.0 API Client DB. Implementing RFC 7591 and RFC 7592:

    - https://tools.ietf.org/html/rfc7591
    - https://tools.ietf.org/html/rfc7592

*/

create extension pgcrypto;

create or replace function client_id_generate()
    returns text as $$
    declare id text;
    begin
        select encode(digest(gen_random_uuid()::text, 'md5'), 'hex') into id;
        return id;
    end;
$$ language plpgsql;


drop table if exists api_clients;
create table if not exists api_clients(
    client_id text not null default client_id_generate() primary key,
    client_id_issued_at timestamptz default current_timestamp,
    client_secret text not null default gen_random_uuid(),
    client_secret_expires_at timestamptz default current_timestamp + '5 years'
        check (client_secret_expires_at > client_id_issued_at),
    redirect_uris text[], -- array_unique
    token_endpoint_auth_method text not null check token_endpoint_auth_method in
        ('none', 'client_secret_post', 'client_secret_basic'),
    grant_types text[] check grant_types in
        ('authorization_code', 'implicit', 'password', 'client_credentials',
         'refresh_token', 'difi'), -- since array, check values in trigger
    response_types text check response_types in ('code', 'token'),
    client_name text unique,
    client_uri text unique,
    logo_uri text unique,
    scopes text[],
    contacts text[], -- array_unique
    tos_uri text,
    policy_uri text, -- needs a server specified default
    jwks_uri text,
    software_id uuid unique,
    software_version text,
    is_active boolean default 't',
    authorized_tentants text[]  -- array_unique, all, pnum
    client_extra_metadata jsonb
    -- and then others for dynamic registration management protocol?
);

comment on column api_clients.client_id
    is 'Unique opaque client identifier';
comment on column api_clients.client_id_issued_at
    is 'Timestamp when client identifier was issued';
comment on column api_clients.client_secret
    is 'Secret for private clients';
comment on column api_clients.client_secret_expires_at
    is 'Timestamp when client secret expires, after which the client
        cannot use the API any longer';
comment on column api_clients.redirect_uris
    is 'List of redirect URIs';
comment on column api_clients.token_endpoint_auth_method
    is 'Which type of _client_ authentication is used at the token endpoint';
comment on column api_clients.grant_types
    is 'A list of authorization grant types which the client is allowed to use';
comment on column api_clients.response_types
    is 'Either code or token, depending on the grant_type';
comment on column api_clients.client_name
    is 'Human readable client name';
comment on column api_clients.client_uri
    is 'URI containing information about the client';
comment on column api_clients.logo_uri
    is 'URI showing the client logo';
comment on column api_clients.scopes
    is 'The OAuth2.0 standard does not specify defaults for scopes:
        https://oauth.net/2/scope/ . It is up to the authorization server
        to decide whether to store any scopes explicitly on a per client
        basis';
comment on column api_clients.contacts
    is 'Email address(es) of client admin';
comment on column api_clients.tos_uri
    is 'Pointer to contractual relationship between end-user and client,
        that the end user accepts when authorizing the client';
comment on column api_clients.policy_uri
    is 'Pointer to a description of how deployment organisation that
        owns the authorization server collects, uses, and retains
        personal data';
comment on column api_clients.jwks_uri
    is 'Reference to document containing the clients public keys';
comment on column api_clients.software_id
    is 'Developer chosen UUID identifyingn the software of the client';
comment on column api_clients.software_version
    is 'Developer chosen version number for the client software';
comment on column api_clients.is_active
    is 'Boolean flag for activation/deactivation of clients by API admins';
comment on column api_clients.authorized_tentants
    is 'List of tenant identifiers specifying which API tenant the client
        can access';
comment on column api_clients.client_extra_metadata
    is 'Unstructured field for extensible client metadata';

-- trigger
-- validate_input: on insert or update, which calls
    -- token_endpoint_auth_method
        -- if none then grant_types, _only_: client_credentials
        -- if client_secret_basic, one of the others
    -- grant_types in verified list
    -- redirect_uris
    -- client_uri
    -- logo_uri
    -- contacts
    -- tos_uri
    -- policy_uri

-- client api:
create or replace function api_client_create(redirect_uris text[],
                                             token_endpoint_auth_method text,
                                             client_name text,
                                             grant_types text,
                                             logo_uri text,
                                             contacts text[],
                                             tos_uri text,
                                             policy_uri text,
                                             jwks_uri text,
                                             software_id text,
                                             software_version text  )
    returns json as $$
    declare client_data json;
    begin
        select json_agg('client_id', client_id) into client_data;
        return client_data;
    end;
$$ language plpgsql;
-- api_client_tenant_add
-- api_client_tenant_remove


-- need a way to transition existing clients to this, transparently :|
-- today's table:

/*
api_key -> ~ client_secrets JWTs with expirations (this is the tricky part)
allowed_auth_modes -> grant_types (basic, tsd, difi)
verified (and confirmed) -> is_active
projects_granted -> authorized_tentants
email -> contact
*/
