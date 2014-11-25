package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.UFAuthAdapter;
import ufront.auth.AuthError;
using tink.CoreApi;

class EasyAuthDBAdapter implements UFAuthAdapter<User> implements UFAuthAdapterSync<User>
{
	var suppliedUsername:String;
	var suppliedPassword:String;

	public function new(username:String, password:String) {
		suppliedUsername = username;
		suppliedPassword = password;
	}

	public function authenticateSync():Outcome<User,AuthError> {
		#if server
			if ( suppliedUsername==null ) return Failure( LoginFailed('No username was supplied') );
			if ( suppliedPassword==null ) return Failure( LoginFailed('No password was supplied') );

			var u = User.manager.select( $username==suppliedUsername );
			if ( u!=null && u.password.length==0 && u.salt.length==0 )
				return Failure( LoginFailed('This user has not finished setting up their password.') );
			if ( u!=null && u.password==User.generatePasswordHash(suppliedPassword,u.salt) )
				return Success( u );
			else
				return Failure( LoginFailed('Username or password was incorrect.') );
		#else 
			return Failure( LoginFailed("EasyAuthDBAdapter can only authenticate() on the server, please use `EasyAuthApi.attemptLogin()`") );
		#end
	}

	public function authenticate():Surprise<User,AuthError> {
		return Future.sync( authenticateSync() );
	}
}