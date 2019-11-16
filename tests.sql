
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

-- public client
select api_client_create('{https://my-average-client.com}',
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
                         '{p11}');



-- TODO
-- only supported grant types
-- for private clients
    -- secret not null
    -- default secret exprity 5y
    -- expiry cannot be before registration, for insert and update
    -- for grant types
        -- authorization_code -> response_type code
        -- password, client_credentials, and refresh -> none
-- for public clients
    -- no secret
    -- no secret expiry
    -- for implicit grant type (only one supported)
        -- response type token
    -- muist have redirect uri
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
