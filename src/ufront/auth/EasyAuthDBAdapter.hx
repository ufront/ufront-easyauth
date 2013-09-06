package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.*;
import ufront.auth.PermissionError;
using tink.core.types.Outcome;

class EasyAuthDBAdapter implements IAuthAdapter<User>
{
	var suppliedUsername:String;
	var suppliedPassword:String;

	public function new(username:String, password:String) {
		suppliedUsername = username;
		suppliedPassword = password;
	}

	public function authenticate():Outcome<User,PermissionError> {
		#if server
			if ( suppliedUsername==null ) { UserError('No username was supplied').asFailure(); }
			if ( suppliedPassword==null ) { UserError('No password was supplied').asFailure(); }

			var u = User.manager.select($username == suppliedUsername);
			if (u != null) 
			{
				if ( u.password==User.generatePasswordHash(suppliedPassword, u.salt) ) {
					return u.asSuccess();
				}
			}
			// If that failed, it must have been wrong...
			return InvalidCredentials('Username or password was incorrect.').asFailure();
		#else 
			return SystemError("DBUserAuthAdapter can only authenticate() on the server").asFailure();
		#end
	}
}