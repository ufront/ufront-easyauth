package ufront.auth.tasks;

import ufront.auth.api.EasyAuthApi;
import ufront.auth.EasyAuthPermissions;
using tink.CoreApi;

#if ufront_uftasks
class EasyAuthTasks extends ufront.tasks.UFTaskSet {
	@:skip @inject public var easyAuthApi:EasyAuthApi;

	/** Create a new user with the given username and password. **/
	public function createUser( username:String, password:String ) {
		easyAuthApi.createUser( username, password ).sure();
	}

	/** Create a new user with the given username and password. **/
	public function createGroup( groupName:String ) {
		easyAuthApi.createGroup( groupName ).sure();
	}

	/** Assign a given permission to a given user. **/
	public function assignPermissionToUser( permission:String, username:String ) {
		var p = getPermissionFromString( permission );
		var u = easyAuthApi.getUserByUsername( username ).sure();
		easyAuthApi.assignPermissionToUser( p, u ).sure();
	}

	/** Assign a given permission to a given group. **/
	public function assignPermissionToGroup( permission:String, group:String ) {
		var p = getPermissionFromString( permission );
		var g = easyAuthApi.getGroupByName( group ).sure();
		easyAuthApi.assignPermissionToGroup( p, g ).sure();
	}

	/** Revoke a given permission from a given user. **/
	public function revokePermissionFromUser( permission:String, username:String ) {
		var p = getPermissionFromString( permission );
		var u = easyAuthApi.getUserByUsername( username ).sure();
		easyAuthApi.revokePermissionFromUser( p, u ).sure();
	}

	/** Revoke a given permission from a given group. **/
	public function revokePermissionFromGroup( permission:String, group:String ) {
		var p = getPermissionFromString( permission );
		var g = easyAuthApi.getGroupByName( group ).sure();
		easyAuthApi.revokePermissionFromGroup( p, g ).sure();
	}

	public function grantSuperPowers( username:String ) {
		var u = easyAuthApi.getUserByUsername( username ).sure();
		easyAuthApi.assignPermissionToUser( EAPCanDoAnything, u ).sure();
	}

	public function revokeSuperPowers( username:String ) {
		var u = easyAuthApi.getUserByUsername( username ).sure();
		easyAuthApi.revokePermissionFromUser( EAPCanDoAnything, u ).sure();
	}

	function getPermissionFromString( permission:String ):EnumValue {
		var parts = permission.split( "." );
		var enumConstructor = parts.pop();
		var enumName = parts.join( "." );
		var enumType = Type.resolveEnum( enumName );
		return Type.createEnum( enumType, enumConstructor, [] );
	}
}
#end
