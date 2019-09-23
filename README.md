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

Other OAuth 2.0 and CAS login providers can be easily added in `src/auth/strategies.ts`

Admins can enable or disable whichever login methods they desire.

## How do I use it?

Ground Truth acts like any other OAuth 2.0 compliant system.

As an admin, visit `/login` and click through to the admin panel. You'll need the name of your application and which URI(s) it will redirect back to once authentication is complete.

This can include something like `http://localhost:3000` during development, but you should remove localhost URLs when running your app in production for better security.

Private / public app type determines whether your app can keep the client secret private (e.g. a typical server-hosted application) or if it is at risk of being revealed (e.g. a mobile app) and should use [PKCE](https://www.oauth.com/oauth2-servers/pkce/) instead.

![Add an OAuth application](https://i.imgur.com/aKxH2mH.png)

Created app
