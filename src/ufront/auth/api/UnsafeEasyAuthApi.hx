package ufront.auth.api;

/**
This API is identical to `EasyAuthApi`, except that it does not check permissions.

**You should only ever use this server side, not over remoting.**
**Be careful to check permissions manually, as this API allows users to assign new permissions to themselves, add themselves to new groups, edit other users and more.**

For example, if you use have permissions `UserCanReceiveSMS` and `UserCanReceiveEmail`, you may wish for the user to be able to turn these on and off themselves.
Using `EasyAuthApi.assignPermissionToUser()` will fail, because a user can't assign a new permission to themselves.
You can use `UnsafeEasyAuthApi.assignPermissionToUser()` to toggle the permissions on and off.
**/
class UnsafeEasyAuthApi extends EasyAuthApi {
	public function new() {
		super();
		unsafeMode = true;
	}
}
