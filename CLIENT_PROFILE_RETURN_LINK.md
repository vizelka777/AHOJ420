# Client Profile Return Link

Use this URL on client side (example: `houbamzdar.cz`) when user should open Ahoj420 profile page and then manually return back:

```
https://ahoj420.eu/?mode=login&edit_profile=1&client_host=houbamzdar.cz&return_to=https%3A%2F%2Fhoubamzdar.cz%2F
```

## Parameters

- `mode=login` — opens login/profile UI flow.
- `edit_profile=1` — disables server auto-resume, so user can edit profile first.
- `client_host=houbamzdar.cz` — label for return button text.
- `return_to=...` — URL-encoded target to return to after profile actions.

## For another client

Replace:
- `client_host` with client domain
- `return_to` with URL-encoded client URL

Example (`client.example`):

```
https://ahoj420.eu/?mode=login&edit_profile=1&client_host=client.example&return_to=https%3A%2F%2Fclient.example%2F
```
