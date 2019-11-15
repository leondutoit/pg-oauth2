
-- api_client_create

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

-- from python, create call_pg_func_named(func_name, params={})
-- https://www.postgresql.org/docs/11/sql-syntax-calling-funcs.html

-- public client
select api_client_create('{https://my-average-client.com}',
                         'none',
                         'TheBestService',
                         'implicit',
                         'https://logo.org',
                         '{leon@dutoit.com}',
                         'https://tos.org',
                         'https://policy.org',
                         'https://jwks.org',
                         '2de1b97e-d32a-48a9-8a9f-cc0c29936afb',
                         'v1',
                         't',
                         '{p11}',
                         null);

-- private client
--select api_client_create('{"https://my-amazing-client.com"}',
  --                       'client_secret_basic');