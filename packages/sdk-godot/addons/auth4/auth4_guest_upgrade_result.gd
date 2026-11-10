class_name Auth4GuestUpgradeResult
extends RefCounted
## The upgraded session and the credential that was linked to the guest.

## The replacement session. Its user_id is the guest's.
var session: Auth4Session
var identity_id := ""
## The linked provider name, such as email, discord, steam, epic, google, apple or microsoft.
var provider := ""
