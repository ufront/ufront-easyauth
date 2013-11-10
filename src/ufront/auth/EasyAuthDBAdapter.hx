package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.*;
import ufront.auth.PermissionError;
using tink.CoreApi;

class EasyAuthDBAdapter implements UFAuthAdapter<User>
{
	var suppliedUsername:String;
	var suppliedPassword:String;

	public function new(username:String, password:String) {
		suppliedUsername = username;
		suppliedPassword = password;
	}

	public function authenticate():Surprise<User,PermissionError> {
		var t = Future.trigger();

		#if server
			if ( suppliedUsername==null ) t.trigger( Failure(UserError('No username was supplied')) );
			if ( suppliedPassword==null ) t.trigger( Failure(UserError('No password was supplied')) );

			var u = User.manager.select( $username==suppliedUsername );
			if (u != null) {
				if ( u.password==User.generatePasswordHash(suppliedPassword, u.salt) ) {
					t.trigger( Success(u) );
				}
			}
			// If that failed, it must have been wrong...
			t.trigger( Failure(InvalidCredentials('Username or password was incorrect.')) );
		#else 
			t.trigger( Failure(SystemError("DBUserAuthAdapter can only authenticate() on the server")) );
		#end

		return t.asFuture();
	}
}