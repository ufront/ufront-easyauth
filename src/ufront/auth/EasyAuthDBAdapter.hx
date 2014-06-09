package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.UFAuthAdapter;
import ufront.auth.PermissionError;
using tink.CoreApi;

class EasyAuthDBAdapter implements UFAuthAdapter<User> implements UFAuthAdapterSync<User>
{
	var suppliedUsername:String;
	var suppliedPassword:String;

	public function new(username:String, password:String) {
		suppliedUsername = username;
		suppliedPassword = password;
	}

	public function authenticateSync():Outcome<User,PermissionError> {
		#if server
			if ( suppliedUsername==null ) return Failure( UserError('No username was supplied') );
			if ( suppliedPassword==null ) return Failure( UserError('No password was supplied') );

			var u = User.manager.select( $username==suppliedUsername );
			return
				if ( u!=null && u.password==User.generatePasswordHash(suppliedPassword,u.salt) )
					return Success( u );
				else
					return Failure( InvalidCredentials('Username or password was incorrect.') );
		#else 
			return Failure( SystemError("EasyAuthDBAdapter can only authenticate() on the server, please use `EasyAuth.api.authenticate()`") );
		#end
	}

	public function authenticate():Surprise<User,PermissionError> {
		return Future.sync( authenticateSync() );
	}
}