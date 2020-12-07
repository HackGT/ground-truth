# HackGT Ground Truth 🛰️

Single sign on for hackathon apps and services using OAuth 2.0

## What is it?

Ground Truth is an authentication mechanism for various hackathon services. It replaces various email / password systems living  in multiple apps in favor of a single, long lived account that can be easily reused.

For example, at HackGT, we use Ground Truth to provide authentication for:
* [Event registration](https://github.com/HackGT/registration)
	* Users don't have to create a new account for every HackGT, HackGTeeny, BuildGT, or HackGT: Horizons event, reducing confusion.
* Event check-in and badge scanning (organizing staff only)
* Team formation site
* HackGT event mobile app

## Why should I use it?

Ground Truth allows participants to create a single HackGT account that stays around for their college careers as they apply to various HackGT-hosted hackathons. This reduces confusion about whether participants already have an account or not and makes for a simpler, streamlined registration and login process.

Additionally, by consolidating all authentication code into a single, dedicated repository, Ground Truth allows for better security auditing and practices that would be impractical in multiple codebases. While non-dedicated authentication systems might only support insecure username / password logins, integrating with Ground Truth allows for external provider login (e.g. Google, GitHub, Facebook) as well as FIDO2 passwordless login and two factor authentication.

## What can it do?

Ground Truth allows users to log in to their HackGT account using the following methods:

* Conventional password
	* Support for FIDO U2F coming soon
* Google
* GitHub
* Facebook
* [Georgia Tech CAS login system](https://login.gatech.edu)
* FIDO2 passwordless login using a security key

Other OAuth 2.0 and CAS login providers can be easily added in `src/auth/strategies`

Admins can enable or disable whichever login methods they desire.

## How to Run

To setup, please configure the `config.json` file in `src/config`. Additionally, Ground Truth can use environment variables for setup for use in production. The names of these variables can be found in `src/common.ts`. Note, you only need to fill in the secrets for the services you will be using.

After filling in the config file or the environment variables, follow these steps:

1. `npm install`
2. `npm start`

## How do I use it?

Ground Truth acts like any other OAuth 2.0 compliant system.

As an admin, visit `/login` and click through to the admin panel.

### Apps

To create an app, you'll need the name of your application and which URI(s) it will redirect back to once authentication is complete.

This can include something like `http://localhost:3000` during development, but you should ideally create different development and production apps for better security.

![Add an OAuth application](https://i.imgur.com/aKxH2mH.png)

Private / public app type determines whether your app can keep the client secret private (e.g. a typical server-hosted application) or if it is at risk of being revealed (e.g. a mobile app) and should use [PKCE](https://www.oauth.com/oauth2-servers/pkce/) instead.

Once an app is created, it's name and redirect URIs can be changed after. Additionally, its secret can be regenerated and the app can be deleted when needed.

### Scopes

Scopes allow an application to access more information about a user. When an application provides a scope when authenticating, Ground Truth will include the information in the user data, and will ask the user for the necessary information if needed.

Examples of scopes include asking for a slack username or a phone number.

![Add a scope](https://i.imgur.com/QLByfds.png)

The scope question field determines the question to show to the user when asking for this information. The input type follows [HTML input types](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input#Form_%3Cinput%3E_types) and the icon field can be any [font awesome icon](https://fontawesome.com/icons?d=gallery&s=solid).

If the scope needs to be validated, both the validation code and validation error messaged need to be provided. The validation works by using the Node.js `vm.runInNewContext()` [method](https://www.geeksforgeeks.org/node-js-vm-runinnewcontext-method/). The context object provided is of TypeScript type `IScopeValidatorContext` and contains these fields:
```js
{
	name, 	// Name of user
	email, 	// Email of user
	scope, 	// Name of scope
	type, 	// Input type of scope
	value 	// The value the user provides
}
```

An example validator that can be used for a phone number is `(/^\(?(\d){3}\)? ?(\d){3}-?(\d){4}$/).test(value)`.

## How do I integrate it?
Ground Truth follows standard [OAuth 2 protocol](https://auth0.com/docs/protocols/protocol-oauth2).

Here are the URLs Ground Truth uses for authentication:
- Authorization URL: `/oauth/authorize`
- Token URL: `/oauth/token`
See the API Reference below for more information.

After authorization, use the `/api/user` endpoint via GET to access user data. Authentication is done with a bearer token using the access token. The API will return a JSON with these fields of the user:
```js
{
	uuid,			// UUID
	name,			// Formatted full name
	nameParts: {
		first,		// First name
		preferred,	// Preferred name (if provided)
		last		// Last name
	},
	admin,			// Boolean value if user is admin
	member,			// Boolean value if user is member
	email,			// Email
	scopes			// Object of scope data
}
```

## OAuth API Reference

### GET `/oauth/authorize`
Endpoint to start OAuth flow 
| Parameter | Description |
|---|---|
| `response_type` | Tells the authorization server which grant to execute |
| `client_id` | 	The ID of the application asking for authorization |
| `redirect_uri` | The URL to redirect to after a successful response |
| `scope` | _(Optional)_ A space-delimited list of permissions that the application requires |
| `code_challenge` | _(Optional - PKCE)_ A code challenge string based on the client generated code verifier
| `code_challenge_method` | _(Optional - PKCE)_ Supports SHA256 hash - `S256` |

### POST `/oauth/token`
Exchanges an authorization code for an access token
| Parameter | Description |
|---|---|
| `grant_type` | Tells the authorization server which grant to execute |
| `code` | 	The authorization code provided from the redirect to exchange for an access token |
| `redirect_uri` | The redirect URL that was used in the initial request |
| `code_verifier` | _(Optional - PKCE)_ The code verifier for the PKCE request, that the app originally generated before the authorization request


