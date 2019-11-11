
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
         'refresh_token', 'difi'), -- latter == custom
    response_types text check response_types in ('code', 'token'),
    client_name text unique,
    client_uri text unique,
    logo_uri text unique,
    scope text[], -- array_unique, (from client) space separated list, need defaults and references
    contacts text[], -- array_unique
    tos_uri text,
    policy_uri text, -- default
    jwks_uri text, -- default
    software_id uuid unique,
    software_version text,
    -- custom params
    is_active boolean default 't',
    authorized_tentants text[]  -- array_unique, all, pnum
    -- and then others for dynamic registration protocol?
);
-- trigger
-- validate_input: on insert or update, which calls
    -- redirect_uris
    -- client_uri
    -- logo_uri
    -- contacts
    -- tos_uri
    -- policy_uri

-- client api:
-- api_client_create
-- api_client_tenant_authorize


-- need a way to transition existing clients to this, transparently :|
-- today's table:

/*
client_id -> currently md5s
api_key -> JWTs with expirations
allowed_auth_modes -> grant_types (basic, tsd, difi)
verified (and confirmed) -> would be the same
projects_granted _. authorized_tentants
email -> contact
*/
