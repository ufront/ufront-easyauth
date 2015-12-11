1.0.0
=====

User, Group and Permission models:

- __New:__ Easily include permissions to send to the client with `user.withPermissions()` function.
- __Improved:__ Change default serialization of `User` to not include the salt or password, so that these are not sent to the client. This also removed the need for the `user.removeSensitiveData()` function, which has been removed.
- __Improved:__ Validate that a `Permission` is related to at least one `User` or `Group`.
- __Changed:__ `Permission.getPermissionID()` is now `Permission.getPermissionString()`.
- __Fixed:__ Make sure the cached `currentUser` is reset after login or logout.


Auth Handlers and Middleware:

- __New:__ Add EasyAuthClient (and matching middleware)
- __Improved:__ EasyAuth now uses constructor dependency injection, rather than `@post` dependency injection. This also means the `sessionVariableName` and `context` variables are now private.
- __Improved:__ Require the EAPCanLogInAsAnotherUser permission for EasyAuth.setCurrentUser() to work.
- __Changed:__ `InlineEasyAuthMiddleware` no longer initiates sessions for you. You can use `InlineSessionMiddleware` or something similar. The code is now significantly cleaner and more inline with the expected behaviour.
- __Fixed:__ `EasyAuth.getCurrentUser()` will now return null (rather than throw an error) if a session is not initialized.


APIs:

- __New:__ Add EasyAuthApi.getCurrentlyLoggedInUser()
- __New:__ Add async proxies for `EasyAuthApi`.
- __Improved:__ Include user permissions when calling `getCurrentUser()`.
- __Improved:__ Better error messages on failed API calls.
- __Improved:__ `attemptLogin()` and `authenticate()` are now asynchronous.
- __Improved:__ `changeCurrentUserPassword()` improved to use an injected `UFAuthAdapter` in the same way as `attemptLogin()`
- __Fixed:__ `isLoggedIn()` - Check session is active before attempting to get a value.
- __Fixed:__ When instantiating the `UFAuthAdapter`, use a temporary injector so that we do not inject 'username' and 'password' into the main injector.

General:

- __New:__ Add `import ufront.EasyAuth` shortcut.
- __Improved:__ Improved API documentation.
- __Improved:__ Add documentation to EasyAuthTasks.






---

Older changes
=============

For changes prior to 1.0.0, please see http://lib.haxe.org/p/ufront-easyauth/versions/
