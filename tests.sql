
/*
https://tools.ietf.org/html/rfc7591#page-16

POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com

{
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2"],
    "client_name": "My Example Client",
    "client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
    "token_endpoint_auth_method": "client_secret_basic",
    "logo_uri": "https://client.example.org/logo.png",
    "jwks_uri": "https://client.example.org/my_public_keys.jwks",
    "example_extension_parameter": "example_value"
}
*/

create or replace function test_private_clients()
    returns boolean as $$
    declare id uuid;
    declare resp json;
    begin
        id := gen_random_uuid();
        select api_client_create(
                         '{https://service1.com}',
                         'service1',
                         '{authorization_code}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
        assert (select client_secret from api_clients where client_name = 'service1')
                is not null, 'private client missing secret';
        assert (select client_secret_expires_at from api_clients where client_name = 'service1')
                between now() - interval '1 hour' and now() + interval '6 years',
                'default secret expiry wrong';
        begin
            update api_clients set client_secret_expires_at = now() - interval '1 day'
                where client_name = 'service1';
        exception when assert_failure then
            raise notice 'client secret cannot be updated to before registration date- as expected';
        end;
        assert (select response_types from api_clients where client_name = 'service1')
                ='code', 'authorization_code has wrong response_type';
        id := gen_random_uuid();
        select api_client_create(
                         '{https://service2.com}',
                         'service2',
                         '{password}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
        assert (select response_types from api_clients where client_name = 'service2')
                = 'none', 'authorization_code has wrong response_type';
        id := gen_random_uuid();
        select api_client_create(
                         '{https://service3.com}',
                         'service3',
                         '{client_credentials}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
        assert (select response_types from api_clients where client_name = 'service3')
                = 'none', 'client_credentials has wrong response_type';
        id := gen_random_uuid();
        select api_client_create(
                         '{https://service4.com}',
                         'service4',
                         '{password,refresh_token}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
        assert (select response_types from api_clients where client_name = 'service4')
                = 'none', 'refresh grant has wrong response_type';
        return true;
    end;
$$ language plpgsql;


create or replace function test_public_clients()
    returns boolean as $$
    begin
        -- no secret
        -- no secret expiry
        -- for implicit grant type (only one supported)
            -- response type token
        -- must have redirect uri
        -- do not allow any other grant than implicit
        return true;
    end;
$$ language plpgsql;


create or replace function test_integrity_checks()
    returns boolean as $$
    begin
        -- only supported grant types
        -- all arrays unique
            -- redirect_uris
            -- grant_types
            -- scopes
            -- contacts
            -- authorized_tentants
        -- immutable columns
            -- client_id
            -- client_id_issued_at
        -- url validation and http(s)
        return true;
    end;
$$ language plpgsql;

create or replace function test_array_helper_funcs()
    returns boolean as $$
    begin
        return true;
    end;
$$ language plpgsql;


create or replace function test_client_authnz()
    returns boolean as $$
    declare cid text;
    declare cs text;
    declare resp json;
    declare status json;
    begin
        select api_client_create(
                         '{https://my-average-client.com}',
                         'TheBestService',
                         '{implicit}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         '2de1b97e-d32a-48a9-8a9f-cc0c29936afb',
                         'v1',
                         't',
                         '{p11}') into resp;
        select client_id, client_secret from api_clients
            where client_name = 'TheBestService' into cid, cs;
        -- that it works
        select api_client_authnz(cid, cs, 'p11', 'implicit', null) into status;
        raise info 'status: %', status;
        select api_client_authnz(';drop table api_clients;', cs, 'p11', 'implicit', null) into status;
        raise info 'status: %', status;
        -- test that if client is inactive cannot authenticate
        update api_clients set is_active = 'f';
        select api_client_authnz(cid, cs, 'p11', 'implicit', null) into status;
        raise info 'status: %', status;
        -- and all branches
        return true;
    end;
$$ language plpgsql;

delete from api_clients; --careful...
select test_private_clients();
select test_client_authnz();
