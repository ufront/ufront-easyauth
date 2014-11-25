package ufront.ufadmin.modules;

#if ufront_ufadmin

import ufront.auth.model.*;
import ufront.web.HttpError;
import ufront.auth.EasyAuth;
import ufront.auth.api.EasyAuthApi;
import ufront.web.result.RedirectResult;
using tink.CoreApi;
using CleverSort;

class EasyAuthAdminModule extends UFAdminModule {
	
	@inject public var easyAuth:EasyAuth;
	@inject public var api:EasyAuthApi;
	
	public function new() {
		super( "easyauth", "Authentication" );
	}
	
	@:route("/")
	public function index() {
		return listAllUsers();
	}
	
	@:route("/users/all/")
	public function listAllUsers() {
		return displayUserList( api.getAllUsers().sure(), "All Users" );
	}
	
	function displayUserList( userList:Iterable<User>, title:String ) {
		var users = Lambda.array( userList );
		users.cleverSort( _.username );
		var template = CompileTime.readFile( "/ufront/ufadmin/view/easyauth/list.html" );
		return UFAdminModule.wrapInLayout( title, template, {
			users:users,
			title:title,
		});
	}
	
	@:route("/user/$username/")
	public function showUserProfile( username:String ) {
		var user = api.getUserByUsername( username ).sure();
		if ( user==null )
			throw HttpError.pageNotFound();
		
		var permissions = api.getAllPermissionsForUser( user.id ).sure();
		var template = CompileTime.readFile( "/ufront/ufadmin/view/easyauth/view.html" );
		
		return UFAdminModule.wrapInLayout( 'Viewing User $username', template, {
			id: user.id,
			username: username,
			groups: user.groups,
			permissions: permissions,
		});
	}
	
	@:route("/loginas/$id/")
	public function loginAs( id:Int ) {
		var user = User.manager.get( id );
		if ( user==null )
			throw HttpError.pageNotFound();
		
		easyAuth.setCurrentUser( user );
		return new RedirectResult( "/" );
	}
	
	@:route(GET,"/users/new/")
	public function newUserForm() {
		return "Add a new user!";
	}
	
	@:route("/user/$username/edit/")
	public function editUserForm( username:String ) {
		return 'Edit user $username';
	}
	
	function showUserForm( ?u:User ) {
		var template = CompileTime.readFile( "/ufront/ufadmin/view/easyauth/view.html" );
		return UFAdminModule.wrapInLayout( 'Viewing User ${u.username}', template, {
			id: u.id,
			username: u.username,
		});
	}
}
#end