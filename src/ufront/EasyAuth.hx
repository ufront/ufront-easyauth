package ufront;

/**
Ufront-EasyAuth is the standard way to set up users, groups and permissions in Ufront.

### Users, Groups, Permissions

EasyAuth is built around the idea of Users, Groups and Permissions, all of which are stored in the database.

##### Users

Each visitor is able to log in as a `User`, using a username and password.

```haxe
var user = new User( "jason", "secretpassword" );
user.save();
trace( user.id );       // 1
trace( user.username ); // jason
trace( user.salt );     // eg ";l@p<3OOKmIBVN<xXraC2Re?XIsUvy;4"
trace( user.password ); // eg "d3933c720ebd8b3cd69ccd7ae7b4a59c521f08aaca22bf907da11be6ccffc8f0"
```

So you can see each user is saved to the database with a random salt and a password hash (generated with `PBKDF2`).
This means we cannot ever reverse the hash to see what their password is - we can only ever check that it is correct.

User data is stored in the `auth_user` database.

##### Groups

Each user can belong to different `Group`s.

```haxe
myGroup.users.add( myUser );
myUser.groups.add( myGroup );

for ( group in groups ) {
	trace( group.name );
	for ( user in group ) {
		trace( user.username );
	}
}
```

You can add users to groups using `group.users.add( user )` or `user.groups.add( group )` - it's a simple `ManyToMany` relationship.
You can also use `EasyAuthApi` to manage your groups and users.

Groups are stored in the `auth_groups` database, and the `_join_Group_User` join table.

##### Permissions

As seen in `UFAuthHandler`, Ufront uses simple enums to describe permissions required in your app.

```haxe
enum BlogPermissions {
	WritePosts;
	ModerateComments;
}

@inject public var auth:UFAuthHandler;

auth.hasPermission( WritePosts );
auth.currentUser.can( WritePosts );
auth.requirePermission( ModerateComments );
```

EasyAuth is set up to work with this, and save which permissions each user or group has in the database as using `Permission` objects.

Permissions can be assigned to an individual `User`, or to a `Group` using `EasyAuthApi`.
When we load the permissions a user has, we will load all the permissions they have individually, as well as those they have because of the groups they belong to.

The assignment of permissions are stored in the `auth_permission` table.

### Using EasyAuth in Ufront

`ufront.auth.EasyAuth` can be used as your `UFAuthHandler`.
In fact, if you're compiling with the `ufront-easyuath` haxelib, EasyAuth will be the default UFAuthHandler set in your `UfrontConfiguration`.

This mean:

- Your `HttpContext.auth` property will be an `EasyAuth` instance.
- Your `UFApi.auth` property will be an `EasyAuth` instance.
- Your `HttpContext.currentUser` will be a `User` object if you are logged in.
- All permission checks are based on the current user, the groups they are in, and the permissions assigned to them and their groups, as they are recorded in the database.

You can use `EasyAuthApi` and its proxy classes to create, manage and remove your users, groups and permissions.

If you are building an administration app or a command line utility which needs to interact with `EasyAuth` data, but doesn't require authentication, use `EasyAuthAdminMode` to skip all permission checks.

If you are providing a stateless API, which needs to work without sessions or a sequence of login requests, then `InlineEasyAuthMiddleware` will help you provide inline authentication in your requests.

If you are using Ufront-UFTasks you can include `EasyAuthTasks` for some basic command line tasks.

If you are using Ufront-UFAdmin the `EasyAuthAdminModule` provides some basic administration capabilities, but is still a work in progress.

##### Using a different authentication system

If you want to use EasyAuth for managing your users, groups, and permissions, but want to authenticate your users differently, you can use a different `UFAuthAdapter`.

The default `EasyAuthDBAdapter` uses the username, salt and hashed password from the `auth_user` table to verify credentials.

By using a custom `UFAuthAdapter`, you could for example:

- Authenticate using a different password hashing algorithm
- Check a password against an LDAP service
- Use a 3rd party login system like OAuth

### Import shortcuts

The `ufront.EasyAuth` module contains typedefs for commonly imported types in the `ufront-easyauth` package.

This allows you to use `import ufront.EasyAuth;` rather than having lots of imports in your code.
**/

// `ufront.auth` package.
#if server
	typedef EasyAuth = ufront.auth.EasyAuth;
	@:noDoc @:noUsing typedef EasyAuthAdminMode = ufront.auth.EasyAuth.EasyAuthAdminMode;
	@:noDoc @:noUsing typedef InlineEasyAuthMiddleware = ufront.auth.InlineEasyAuthMiddleware;
#elseif client
	@:noDoc @:noUsing typedef EasyAuthClient = ufront.auth.EasyAuthClient;
	@:noDoc @:noUsing typedef InlineEasyAuthClientMiddleware = ufront.auth.InlineEasyAuthClientMiddleware;
#end
@:noDoc @:noUsing typedef EasyAuthDBAdapter = ufront.auth.EasyAuthDBAdapter;
@:noDoc @:noUsing typedef EasyAuthLoginErrorMessage = ufront.auth.EasyAuthDBAdapter.EasyAuthLoginErrorMessage;
@:noDoc @:noUsing typedef EasyAuthPermissions = ufront.auth.EasyAuthPermissions;

// `ufront.auth.api` package.
@:noDoc @:noUsing typedef EasyAuthApi = ufront.auth.api.EasyAuthApi;
@:noDoc @:noUsing typedef EasyAuthApiAsync = ufront.auth.api.EasyAuthApi.EasyAuthApiAsync;
@:noDoc @:noUsing typedef EasyAuthApiAsyncCallback = ufront.auth.api.EasyAuthApi.EasyAuthApiAsyncCallback;

// `ufront.auth.api.model` package.
@:noDoc @:noUsing typedef Group = ufront.auth.model.Group;
@:noDoc @:noUsing typedef Permission = ufront.auth.model.Permission;
@:noDoc @:noUsing typedef User = ufront.auth.model.User;

// `ufront.auth.api.tasks` package.
#if ufront_uftasks
	@:noDoc @:noUsing typedef EasyAuthTasks = ufront.auth.tasks.EasyAuthTasks;
#end

// `ufront.ufadmin.modules.easyauth` package.
#if ufront_ufadmin
	@:noDoc @:noUsing typedef EasyAuthAdminModule = ufront.ufadmin.modules.easyauth.EasyAuthAdminModule;
#end
