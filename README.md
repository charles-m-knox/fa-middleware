# fa-middleware

This repository contains the building blocks for a FusionAuth-based middleware layer, written in Go.

## Table of Contents

- [fa-middleware](#fa-middleware)
  - [Table of Contents](#table-of-contents)
  - [Getting started](#getting-started)
  - [References](#references)
  - [Fusion Auth](#fusion-auth)
    - [Login directly](#login-directly)
  - [Managing the database](#managing-the-database)
  - [Needed features](#needed-features)
  - [Schema discussion](#schema-discussion)
    - [Table definition](#table-definition)
  - [TODO](#todo)

## Getting started

For the first time:

1. Run `make run-fa`
2. Set up FusionAuth by visiting `http://localhost:9011`
3. Set up the steps in https://fusionauth.io/docs/v1/tech/5-minute-setup-guide/
  1. Make sure to set up your application to not require API keys on login:
    1. Add application -> Security -> Require an API Key (off)
  2. Set up your application to allow self-service registration:
    1. Add application -> Registration
  3. Create an api key:
    1. Left sidebar -> Settings -> API Keys
    2. Click GET/POST/PUT/PATCH/DELETE to enable the API key to have global access
4. Set the bind ports and other options in `.env` and in `./res/config.yml` based on their `.example` variants.
5. Set the secrets from the application in `./res/config.yml` accordingly
6. Run `make run-middleware` to run the middleware now that it's been properly configured
7. Visit `http://localhost:8080/auth/login` in your browser, or whatever the port/bind address is for your setup
8. Follow the login/registration workflow, brokered by FusionAuth
9. Observe that the callback URL has been hit after logging in

These are the basic steps to get this middleware up and running. Up next is to get frontend interactions working with this layer.

## References

* https://github.com/FusionAuth/go-client
* https://fusionauth.io/blog/2020/03/10/securely-implement-oauth-in-react/
* https://fusionauth.io/docs/v1/tech/oauth/endpoints/
* https://fusionauth.io/docs/v1/tech/example-apps/go/
* https://fusionauth.io/blog/2020/06/17/building-cli-app-with-device-grant-and-golang/
* https://fusionauth.io/docs/v1/tech/core-concepts/integration-points/ - **important** - showcases the pages that you don't have to deal with 😉

Useful examples for `gin-gonic`:

* https://gin-gonic.com/docs/examples/bind-query-or-post/
* https://gin-gonic.com/docs/examples/support-lets-encrypt/
* https://gin-gonic.com/docs/examples/goroutines-inside-a-middleware/

Useful content for Postgres:

* https://www.postgresqltutorial.com/postgresql-date/
* https://www.prisma.io/dataguide/postgresql/inserting-and-modifying-data/insert-on-conflict

## Fusion Auth

Examples relating to FusionAuth directly.

### Login directly

https://fusionauth.io/docs/v1/tech/apis/login/#authenticate-a-user

```bash
curl -vvv -X POST -H "Content-Type: application/json" -d '{"loginId":"test2@site.com","password":"password1234","applicationId":"4ef26681-80e6-4c6e-895f-3ef45321a2cd","noJWT":false,"ipAddress":"192.168.0.10"}' http://localhost:9011/api/login
```

## Managing the database

Using `adminer`, which is included in the docker compose file, you can navigate to `http://localhost:9015` and log in to the postgres db.

## Needed features

* Support user management API endpoints: https://fusionauth.io/docs/v1/tech/apis/users/#create-a-user
  * Password reset API endpoint, or figure out how to do it in FusionAuth
  * Change password API endpoint, or figure out how to do it in FusionAuth
  * Updating a user's info https://fusionauth.io/docs/v1/tech/apis/users/#update-a-user
* Multi-tenancy - multiple apps should be able to interface via this middleware into a single FusionAuth instance
* Stripe integration - complements multi-tenancy by enabling payments to be tracked across different projects

## Schema discussion

FusionAuth does offer a "user data" key-value storage, which is great, but I think it's more important to have a postgresql database that is dedicated to this purpose. We can guarantee scalable queries instead of having to deal with an extra API.

There are two (or three) critical identifiers that need to be handled:

* The Stripe customer id, such as `cus_J6Tc1xnIxNW5BG`
* The FusionAuth user id, such as `370df073-c2e3-41f9-a64f-32866a48b972`
* The tenant ID, for multi-tenancy scenarios where we have many apps landed on a single FusionAuth instance, such as `cbb8cd3a-aed7-413c-a65f-40acf4034fc3`

These associations can be stored in a few locations:

* FusionAuth can store the Stripe customer ID as a user data key/value pair
* A customer in Stripe can have arbitrary metadata, so we should put the tenant ID and user ID there
* All three can be stored in a local postgres DB

It might be smartest to store all three of these for the sake of ensuring that the data is always viewable on each platform - Stripe, FusionAuth, and queryable locally without having to hammer away at a 3rd party API (FusionAuth won't be third party since it's local, but the API itself is subject to third party design).

### Table definition

This is an initial draft of a possible database schema:

| `id`                                   | `app_id`                               | `tenant_id`                            | `stripe_cust_id`     | `field`    | `value` | `updated_at` |
| -------------------------------------- | -------------------------------------- | -------------------------------------- | -------------------- | ---------- | ------- | ------------ |
| `370df073-c2e3-41f9-a64f-32866a48b972` | `6e4b577c-6752-46db-9c42-3bd86858c59d` | `cbb8cd3a-aed7-413c-a65f-40acf4034fc3` | `cus_J6Tc1xnIxNW5BG` | `settings` | `"{}"`  | `<date>`     |

## TODO

* Add a secret key to better secure other microservices' access to the mutation and user data endpoints
