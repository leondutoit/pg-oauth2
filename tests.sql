
/*

Allowed grant type combinations:

authorization_code, refresh_token
implicit
password, client_secret_basic, refresh_token

*/

create or replace function test_private_clients()
    returns boolean as $$
    declare id uuid;
    declare resp json;
    declare sec text;
    declare sec_exp timestamptz;
    declare auth_method text;
    declare resp_type text;
    begin
        -- authorization_code grant
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
        select client_secret, client_secret_expires_at,  token_endpoint_auth_method, response_types
            from api_clients where client_name = 'service1'
            into sec, sec_exp, auth_method, resp_type;
        assert sec is not null, 'private client missing secret';
        assert sec_exp between now() - interval '1 hour' and now() + interval '6 years', 'default secret expiry wrong';
        assert auth_method = 'client_secret_basic', 'private client auth method issue';
        assert resp_type = 'code', 'private client response type issue - authorization_code grant';
        begin
            update api_clients set client_secret_expires_at = now() - interval '1 day'
                where client_name = 'service1';
            raise exception using message = 'problem with client_secret_expires_at restrictions';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set grant_types = array['authorization_code', 'implicit']
                where client_name = 'service1';
            raise exception using message = 'problem with authorization_code grant_type restrictions';
        exception when assert_failure then
            null;
        end;
        -- password grant
        id := gen_random_uuid();
        select api_client_create(
                         null,
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
        select client_secret, client_secret_expires_at,  token_endpoint_auth_method, response_types
            from api_clients where client_name = 'service2'
            into sec, sec_exp, auth_method, resp_type;
        assert sec is not null, 'private client missing secret';
        assert sec_exp between now() - interval '1 hour' and now() + interval '6 years', 'default secret expiry wrong';
        assert auth_method = 'client_secret_basic', 'private client auth method issue';
        assert resp_type = 'none', 'private client response type issue - password grant';
        -- client_credentials
        id := gen_random_uuid();
        select api_client_create(
                         null,
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
        select client_secret, client_secret_expires_at,  token_endpoint_auth_method, response_types
            from api_clients where client_name = 'service3'
            into sec, sec_exp, auth_method, resp_type;
        assert sec is not null, 'private client missing secret';
        assert sec_exp between now() - interval '1 hour' and now() + interval '6 years', 'default secret expiry wrong';
        assert auth_method = 'client_secret_basic', 'private client auth method issue';
        assert resp_type = 'none', 'private client response type issue';
        -- test grant type combinations
        id := gen_random_uuid();
        select api_client_create(
                         null,
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
    declare id uuid;
    declare resp json;
    declare sec text;
    declare sec_exp timestamptz;
    declare resp_type text;
    declare red_uris text[];
    declare cid text;
    declare status boolean;
    begin
        id := gen_random_uuid();
        select api_client_create(
                         '{https://service5.com}',
                         'service5',
                         '{implicit}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
        select client_id, client_secret, client_secret_expires_at, response_types, redirect_uris from api_clients
            where client_name = 'service5' into cid, sec, sec_exp, resp_type, red_uris;
        assert sec is null, 'public client has secret - should not';
        assert sec_exp is null, 'public client has secret expiry - should not';
        assert resp_type = 'token', 'public client has wrong response type';
        assert red_uris is not null, 'public client does not have a redirect uri - it should';
        begin
            select api_client_grant_type_add(cid, 'refresh_token') into status;
            raise info 'public client grant restrictions not working';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set client_secret = 'bla' where client_name = 'service5';
            raise exception using message = 'public clients can set secret - should not';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set client_secret_expires_at = now() where client_name = 'service5';
            raise exception using message = 'public clients can set secret expiry - should not';
        exception when assert_failure then
            null;
        end;
        return true;
    end;
$$ language plpgsql;


create or replace function test_integrity_checks()
    returns boolean as $$
    declare id uuid;
    declare resp json;
    begin
        id := gen_random_uuid();
        begin
            select api_client_create(
                         '{https://service6.com}',
                         'service6',
                         '{nonsense}',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         id::text,
                         'v1',
                         't',
                         '{p11}') into resp;
            raise exception using message = 'grant type restrictions not working';
        exception when assert_failure then
            null;
        end;
        -- all arrays unique
        begin
            update api_clients set redirect_uris = '{https://a.c,https://a.c}' where client_name = 'service5';
            raise exception using message = 'redirect_uris not ensured to be unique';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set grant_types = '{password,password}' where client_name = 'service5';
            raise exception using message = 'grant_types not ensured to be unique';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set scopes = '{bla,bla}' where client_name = 'service5';
            raise exception using message = 'scopes not ensured to be unique';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set contacts = '{l@f.g,l@f.g}' where client_name = 'service5';
            raise exception using message = 'contacts not ensured to be unique';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set authorized_tentants = '{p1,p1}' where client_name = 'service5';
            raise exception using message = 'authorized_tentants not ensured to be unique';
        exception when assert_failure then
            null;
        end;
        -- immutable columns
        begin
            update api_clients set client_id = 'random-thing' where client_name = 'service5';
            raise exception using message = 'possible to change client_id - should not be';
        exception when assert_failure then
            null;
        end;
        begin
            update api_clients set client_id_issued_at = now() where client_name = 'service5';
            raise exception using message = 'possible to change client_id_issued_at - should not be';
        exception when assert_failure then
            null;
        end;
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
select test_public_clients();
select test_integrity_checks();
select test_client_authnz();
