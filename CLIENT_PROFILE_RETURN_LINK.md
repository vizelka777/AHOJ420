# Client Profile Return Link

Use this URL on client side when user should open Ahoj420 profile page, then:
- return via dedicated button to profile page on client
- return after save to a reauth page on client

```
https://ahoj420.eu/?mode=login&edit_profile=1&client_host=houbamzdar.cz&return_profile_to=https%3A%2F%2Fhoubamzdar.cz%2Fme.html&return_after_save_to=https%3A%2F%2Fhoubamzdar.cz%2Freauth.html
```

## Parameters

- `mode=login` — opens login/profile UI flow.
- `edit_profile=1` — disables server auto-resume, so user can edit profile first.
- `client_host=houbamzdar.cz` — label for return button text.
- `return_profile_to=...` — URL-encoded target for the visible "Return" button.
- `return_after_save_to=...` — URL-encoded target used after save (or no changes + save click).
- `return_to=...` — optional fallback (legacy OIDC callback flow).

## For another client

Replace:
- `client_host` with client domain
- `return_to` with URL-encoded client URL

Example (`client.example`):

```
https://ahoj420.eu/?mode=login&edit_profile=1&client_host=client.example&return_profile_to=https%3A%2F%2Fclient.example%2Fme&return_after_save_to=https%3A%2F%2Fclient.example%2Freauth
```
