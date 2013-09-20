package ufront.auth.model;

import ufront.db.Object;
import ufront.db.ManyToMany; 
import sys.db.Types;

import ufront.auth.model.Permission;
import ufront.auth.model.User;

@:table("auth_group")
class Group extends Object
{
	public function new( ?name:String ) {
		super();
		if (name!=null) 
			this.name = name;
	}
	
	public var name:SString<255>;

	public var users:ManyToMany<Group, User>;
	public var permissions:HasMany<Permission>;
}