
/*

OAuth2.0 API Client DB. Implementing RFC 7591 and RFC 7592:

    - https://tools.ietf.org/html/rfc7591
    - https://tools.ietf.org/html/rfc7592

With multi-tenancy.

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
    client_secret text unique,
    client_secret_expires_at timestamptz,
    redirect_uris text[],
    token_endpoint_auth_method text not null
        check (token_endpoint_auth_method in ('none', 'client_secret_post', 'client_secret_basic')),
    grant_types text[] not null,
    response_types text not null check (response_types in ('code', 'token', 'none')),
    client_name text not null unique,
    client_uri text,
    logo_uri text,
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


create or replace function assert_array_unique(arr text[], name text)
    returns void as $$
    declare err text;
    begin
        if arr is not null then
            err := 'duplicate ' || name;
            assert (select cardinality(array(select distinct unnest(arr)))) =
                   (select cardinality(arr)), err;
        end if;
    end;
$$ language plpgsql;


drop table if exists https_only;
create table if not exists https_only(enabled boolean not null);
insert into https_only values ('t');


create or replace function assert_valid_url(arr text[])
    returns void as $$
    declare err text;
    declare element text;
    declare only_https boolean;
    begin
        select enabled from https_only limit 1 into only_https;
        if arr is not null then
            for element in select unnest(arr) loop
                if element is not null then
                    err := 'invalid url: ' || element;
                    if only_https then
                        assert element ~ 'https://.*', err;
                    else
                        assert element ~ '(https://.*|http://.*)', err;
                    end if;
                end if;
            end loop;
        end if;
    end;
$$ language plpgsql;


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
-- ^ move to config?


drop function if exists validate_api_client_input() cascade;
create or replace function validate_api_client_input()
    returns trigger as $$
    declare restriction text;
    declare grant_type text;
    begin
        for grant_type in select unnest(NEW.grant_types) loop
            if grant_type is not null then
                assert grant_type in (select gtype from supported_grant_types),
                    'grant type not supported';
            end if;
        end loop;
        perform assert_valid_url(NEW.redirect_uris);
        perform assert_valid_url(array[NEW.client_uri, NEW.logo_uri, NEW.tos_uri, NEW.policy_uri]);
        perform assert_array_unique(NEW.redirect_uris, 'redirect_uris');
        perform assert_array_unique(NEW.grant_types, 'grant_types');
        perform assert_array_unique(NEW.scopes, 'scopes');
        perform assert_array_unique(NEW.contacts, 'contacts');
        perform assert_array_unique(NEW.authorized_tentants, 'authorized_tentants');
        restriction := 'public client are not allowed to have client secrets';
        if TG_OP = 'INSERT' then
            if array['implicit'] <@ NEW.grant_types then
                -- public client restrictions
                assert NEW.grant_types = array['implicit'], 'public clients can only use implicit grant';
                assert NEW.client_secret is null, restriction;
                assert NEW.client_secret_expires_at is null, restriction;
            else
                assert NEW.client_secret_expires_at > NEW.client_id_issued_at,
                    'expiry before registration makes no sense';
            end if;
        elsif TG_OP = 'UPDATE' then
            assert OLD.client_id = NEW.client_id, 'client_id is immutable';
            assert OLD.client_id_issued_at = NEW.client_id_issued_at, 'client_id_issued_at is immutable';
            if array['implicit'] = OLD.grant_types then
                -- public client restrictions
                assert NEW.grant_types = array['implicit'], 'public clients can only use implicit grant';
                assert OLD.token_endpoint_auth_method = NEW.token_endpoint_auth_method,
                    'public clients cannot change token_endpoint_auth_method';
                assert NEW.client_secret is null, restriction;
                assert NEW.client_secret_expires_at is null, restriction;
            else
                if NEW.client_secret_expires_at is not null then
                    assert NEW.client_secret_expires_at > OLD.client_id_issued_at,
                        'expiry before registration makes no sense';
                end if;
            end if;
        end if;
        return new;
    end;
$$ language plpgsql;
create trigger api_clients_input_validation before insert or update on api_clients
    for each row execute procedure validate_api_client_input();


create or replace function api_client_create(redirect_uris text[],
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
                                             client_extra_metadata json default null)
    returns json as $$
    declare response_type text;
    declare client_data json;
    declare secret text;
    declare secret_expiry timestamptz;
    declare new_name text;
    declare token_endpoint_auth_method text;
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
        secret := gen_random_uuid()::text;
        secret_expiry := current_timestamp + '5 years';
        if grant_type = 'implicit' then
            token_endpoint_auth_method := 'none';
            secret := null;
            secret_expiry := null;
            response_type := 'token';
        else
            token_endpoint_auth_method := 'client_secret_basic';
            -- ^ opinionated choice: do not want POST
        end if;
        if grant_type = 'authorization_code' then
            response_type := 'code';
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
                'client_id', ac.client_id,
                'client_id_issued_at', ac.client_id_issued_at,
                'client_secret', ac.client_secret,
                'client_secret_expires_at', ac.client_secret_expires_at,
                'redirect_uris', ac.redirect_uris,
                'token_endpoint_auth_method', ac.token_endpoint_auth_method,
                'grant_types', ac.grant_types,
                'response_types', ac.response_types,
                'client_name', ac.client_name,
                'client_uri', ac.client_uri,
                'logo_uri', ac.logo_uri,
                'scopes', ac.scopes,
                'contacts', ac.contacts,
                'tos_uri', ac.tos_uri,
                'policy_uri', ac.policy_uri,
                'jwks_uri', ac.jwks_uri,
                'software_id', ac.software_id,
                'software_version', ac.software_version,
                'is_active', ac.is_active,
                'authorized_tentants', ac.authorized_tentants)
            from api_clients ac where ac.client_name = new_name
            into client_data;
        return client_data;
    end;
$$ language plpgsql;


create or replace function api_client_grant_type_add(client_id text, grant_type text)
    returns boolean as $$
    declare current text[];
    declare new text[];
    begin
        select grant_types from api_clients into current;
        select array_append(current, grant_type) into new;
        update api_clients set grant_types = new;
        return true;
    end;
$$ language plpgsql;


create or replace function api_client_grant_type_remove(client_id text, grant_type text)
    returns boolean as $$
    begin
        return true;
    end;
$$ language plpgsql;


create or replace function api_client_tenant_add(client_id text, grant_type text)
    returns boolean as $$
    begin
        return true;
    end;
$$ language plpgsql;


create or replace function api_client_tenant_remove(client_id text, grant_type text)
    returns boolean as $$
    begin
        return true;
    end;
$$ language plpgsql;


create or replace function api_client_expiry_modify(client_id text, expiry text)
    returns boolean as $$
    begin
        return true;
    end;
$$ language plpgsql;


create or replace function api_client_tenant_add(client_id text,
                                                 client_secret text,
                                                 tenant text,
                                                 grant_type text,
                                                 scope text)
    returns boolean as $$
    begin
        -- authn: check credentials
        -- authz: check if tenant, grant_type and scope allowed
        return true;
    end;
$$ language plpgsql;
