class_name Auth4SecureStorage
extends RefCounted
## Contract for platform secure storage, such as the iOS Keychain, Android Keystore-backed
## encrypted storage, Windows DPAPI or a console vendor's protected save API, usually reached
## through a GDExtension or an Android or iOS plugin. Implementations must encrypt at rest with an
## OS-protected key and must never write to user://, ConfigFile, ProjectSettings, plain files or
## logs. Refresh tokens are persisted only when an adapter is supplied explicitly; the addon ships
## no persistent adapter. Methods may be coroutines.


## Returns the stored value, or null when the key is absent.
func read(_key: String) -> Variant:
	push_error("Auth4SecureStorage.read() is not implemented.")
	return null


## Returns true once the value is stored.
func write(_key: String, _value: String) -> bool:
	push_error("Auth4SecureStorage.write() is not implemented.")
	return false


## Returns true once the key is absent.
func delete(_key: String) -> bool:
	push_error("Auth4SecureStorage.delete() is not implemented.")
	return false
