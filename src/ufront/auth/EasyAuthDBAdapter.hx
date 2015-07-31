package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.UFAuthAdapter;
import ufront.auth.AuthError;
import ufront.web.HttpError;
import tink.core.Error;
using tink.CoreApi;

class EasyAuthDBAdapter implements UFAuthAdapter<User> implements UFAuthAdapterSync<User> {

	var username:String;
	var password:String;

	/**
	@param username The username to use when attempting authentication. Can be injected as a String named "username".
	@param password The password to use when attempting authentication. Can be injected as a String named "password".
	**/
	@inject("username","password")
	public function new(username:String, password:String) {
		this.username = username;
		this.password = password;
	}

	public function authenticateSync():Outcome<User,TypedError<AuthError>> {
		#if server
			if ( username==null ) return Failure( HttpError.authError(ALoginFailed(NoUsername)) );
			if ( password==null ) return Failure( HttpError.authError(ALoginFailed(NoPassword)) );

			var u = User.manager.select( $username==username );
			if ( u!=null && u.password.length==0 && u.salt.length==0 )
				return Failure( HttpError.authError(ALoginFailed(NotSetUp)) );
			if ( u!=null && u.password==User.generatePasswordHash(password,u.salt) )
				return Success( u );
			else
				return Failure( HttpError.authError(ALoginFailed(IncorrectDetails)) );
		#else
			return Failure( HttpError.authError(ALoginFailed("EasyAuthDBAdapter can only authenticate() on the server, please use `EasyAuthApi.attemptLogin()`")) );
		#end
	}

	public function authenticate():Surprise<User,TypedError<AuthError>> {
		return Future.sync( authenticateSync() );
	}
}

@:enum abstract EasyAuthLoginErrorMessage(String) to String {
	var NoUsername = 'No username was supplied';
	var NoPassword = 'No password was supplied';
	var NotSetUp = 'This user has not finished setting up their password.';
	var IncorrectDetails = 'IncorrectDetails';
}
