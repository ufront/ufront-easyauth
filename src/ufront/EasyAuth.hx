package ufront;

/**
The `ufront.EasyAuth` module contains typedefs for commonly imported types in the `ufront-orm` package.

This allows you to use `import ufront.EasyAuth;` rather than having lots of imports in your code.
**/

// `ufront.auth` package.
#if server
	@:noDoc @:noUsing typedef EasyAuth = ufront.auth.EasyAuth;
	@:noDoc @:noUsing typedef EasyAuthAdminMode = ufront.auth.EasyAuth.EasyAuthAdminMode;
	@:noDoc @:noUsing typedef InlineEasyAuthMiddleware = ufront.auth.InlineEasyAuthMiddleware;
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
