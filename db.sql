
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
    client_id_issued_at timestamptz not null default current_timestamp,
    client_secret text,
    client_secret_expires_at timestamptz,
    redirect_uris text[],
    token_endpoint_auth_method text not null check (token_endpoint_auth_method in
        ('none', 'client_secret_post', 'client_secret_basic')),
    grant_types text[] not null,
    response_types text not null check (response_types in ('code', 'token', 'none')),
    client_name text not null unique,
    client_uri text unique,
    logo_uri text unique,
    scopes text[],
    contacts text[] not null,
    tos_uri text,
    policy_uri text,
    jwks_uri text,
    software_id uuid unique,
    software_version text,
    is_active boolean not null default 't',
    authorized_tentants text[],
    client_extra_metadata jsonb
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


drop function if exists validate_api_client_input() cascade;
create or replace function validate_api_client_input()
    returns trigger as $$
    begin
        -- for both insert and update
        -- array_unique
            -- redirect_uris
            -- grant_types
            -- scopes
            -- contacts
            -- authorized_tentants
        -- validate uris
            -- client_uri
            -- logo_uri
            -- tos_uri
            -- policy_uri
        -- if client_secret, check secret exp date > issued at date
        if TG_OP = 'INSERT' then
            null; -- maybe this is not necessary
        elsif TG_OP = 'UPDATE' then
            -- immutable fields
                -- client_id
                -- client_id_issued_at
            null;
            -- ensure that if token_endpoint_auth_method = none, then grant_type is immutable
        end if;
        return new;
    end;
$$ language plpgsql;
create trigger api_clients_input_validation before insert or update on api_clients
    for each row execute procedure validate_api_client_input();


drop table if exists supported_grant_types;
create table supported_grant_types(
    gtype text unique not null
);
insert into supported_grant_types values ('authorization_code');
insert into supported_grant_types values ('implicit');
insert into supported_grant_types values ('password');
insert into supported_grant_types values ('client_credentials');
insert into supported_grant_types values ('refresh_token');
insert into supported_grant_types values ('difi'); -- custom
insert into supported_grant_types values ('dataporten'); -- custom
insert into supported_grant_types values ('elixir'); -- custom


create or replace function api_client_create(redirect_uris text[],
                                             token_endpoint_auth_method text,
                                             client_name text,
                                             grant_type text,
                                             logo_uri text,
                                             contacts text[],
                                             tos_uri text,
                                             policy_uri text,
                                             jwks_uri text,
                                             software_id text,
                                             software_version text,
                                             is_active boolean,
                                             authorized_tenants text[],
                                             client_extra_metadata json)
    returns json as $$
    declare response_type text;
    declare client_data json;
    declare secret text;
    declare secret_expiry timestamptz;
    declare new_name text;
    begin
        /*

        https://tools.ietf.org/html/rfc7591#section-2.1

        grant_type          response_type (at authorization endpoint)
        ----------          -------------
        authorization_code  code
        implicit            token
        password            none (uses token endpoint)
        client_credentials  none (uses token endpoint)
        refresh_token       none (uses token endpoint)

        */
        assert grant_type in (select gtype from supported_grant_types), 'grant type not supported';
        secret := gen_random_uuid()::text;
        secret_expiry := current_timestamp + '5 years';
        if token_endpoint_auth_method = 'none' then
            assert grant_type = 'implicit', 'public clients can only use implicit flow';
            secret := null;
            secret_expiry := null;
        end if;
        if grant_type = 'authorization_code' then
            response_type := 'code';
        elsif grant_type = 'implicit' then
            response_type := 'token';
        else
            response_type := 'none';
        end if;
        new_name := client_name;
        insert into api_clients
            (client_secret, client_secret_expires_at,
             redirect_uris, token_endpoint_auth_method,
             client_name, grant_types, response_types,
             logo_uri, contacts, tos_uri, policy_uri,
             jwks_uri, software_id, software_version,
             is_active, authorized_tentants, client_extra_metadata)
        values
            (secret, secret_expiry,
             redirect_uris, token_endpoint_auth_method,
             client_name, array[grant_type], response_type,
             logo_uri, contacts, tos_uri, policy_uri,
             jwks_uri, software_id::uuid, software_version,
             is_active, authorized_tenants, client_extra_metadata);
        select json_build_object(
                'client_id', ac.client_id)
            from api_clients ac where ac.client_name = new_name
            into client_data;
        return client_data;
    end;
$$ language plpgsql;


-- api_clients_grant_add
-- api_clients_grant_remove
-- api_client_tenant_add
-- api_client_tenant_remove


/*
transition:
api_key -> ~ client_secrets JWTs with expirations (this is the tricky part)
allowed_auth_modes -> grant_types (basic, tsd, difi)
verified (and confirmed) -> is_active
projects_granted -> authorized_tentants
email -> contact
*/
