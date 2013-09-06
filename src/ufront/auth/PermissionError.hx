package ufront.auth;

@:keep enum PermissionError
{
	InvalidCredentials(msg:String);
	NotLoggedIn(msg:String);
	DoesNotHavePermission(msg:String);
	UserError(msg:String);
	SystemError(msg:String);
}