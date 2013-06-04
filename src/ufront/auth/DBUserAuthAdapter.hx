package ufront.auth;

import ufront.auth.*;
import ufront.auth.model.User;
import ufront.auth.*;
import thx.util.Message;

class DBUserAuthAdapter implements IAuthAdapter<User>
{
	var suppliedUsername:String;
	var suppliedPassword:String;

	public function new(username:String, password:String)
	{
		suppliedUsername = username;
		suppliedPassword = password;
	}

	public function authenticate():AuthResult<User>
	{
		#if server
		if (suppliedUsername == null) { return new AuthResult(Failure(new Message('No username was supplied'))); }
		if (suppliedPassword == null) { return new AuthResult(Failure(new Message('No password was supplied'))); }

		var u = User.manager.select($username == suppliedUsername);
		if (u != null) 
		{
			if (u.password == User.generatePasswordHash(suppliedPassword, u.salt))
			{
				return new AuthResult(Success, u.removeSensitiveData());
			}
		}
		return new AuthResult(InvalidCredential(new Message('Username or password was incorrect.')));
		#end
		return null;
	}
}