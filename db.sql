
/* OAuth2.0 API Client DB, implementing RFC 7591 and RFC 7592 */

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
    client_id uuid not null default client_id_generate() primary key,
    client_id_issued_at timestamptz default current_timestamp,
    client_secret text not null default gen_random_uuid(), -- for anon clients, just don't return it
    client_secret_expires_at timestamptz default current_timestamp + '5 years'
        check (client_secret_expires_at > client_id_issued_at),
    redirect_uris text[], -- array_unique
    token_endpoint_auth_method text check token_endpoint_auth_method in
        ('none', 'client_secret_post', 'client_secret_basic'),
    grant_types text[] check grant_types in
        ('authorization_code', 'implicit', 'password', 'client_credentials',
         'refresh_token', 'difi'), -- latter == custom, check wont work on array as is
    response_types text check response_types in ('code', 'token'),
    client_name text unique,
    client_uri text unique,
    logo_uri text unique,
    scopes text[],
    contacts text[], -- array_unique
    tos_uri text,
    policy_uri text, -- default
    jwks_uri text, -- default
    software_id uuid unique,
    software_version text,
    -- custom params
    is_active boolean default 't', --default to true?
    authorized_tentants text[]  -- array_unique, all, pnum
    -- and then others for dynamic registration protocol?
);

comment on column api_clients.client_id is
    '';
comment on column api_clients.scopes is
    'The OAuth2.0 standard does not specify defaults for scopes:
     https://oauth.net/2/scope/ . It is up to the authorization server
     to decide whether to store any scopes explicitly on a per client
     basis';

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
