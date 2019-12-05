
# pg-oauth2

DB tools for implementing OAuth2.0 authorization servers.

## Setup

Set up the db, run the tests:
```bash
psql -U $DBOWNER -d $DBNAME -f db.sql
# note: running the tests will remove/insert data
psql -U $DBOWNER -d $DBNAME -f tests.sql
```

## SQL API

The following convenience functions are supplied, in addition to the `api_clients` table:

```txt
api_client_create(redirect_uris text[],
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

api_client_grant_type_add(client_id text, grant_type text)
api_client_grant_type_remove(client_id text, grant_type text)

api_client_tenant_add(client_id text, tenant text)
api_client_tenant_remove(client_id text, tenant text)

api_client_authnz(client_id text,
                  client_secret text,
                  tenant text,
                  grant_type text,
                  scope text)
```

For the details of the `api_clients` table, do `\d+ api_clients` in the psql shell. For example usage of the SQL API see `tests.sql`.

## Customisation

By default the library supports these grants:

- authorization_code
- implicit
- password
- client_credentials
- refresh_token

If you want to add more grants then do:

```sql
insert into supported_grant_types values ('your-grant-name-here');
```

## License

BSD.
