const Main = imports.ui.main;
const GLib = imports.gi.GLib;
const PopupMenu = imports.ui.popupMenu;

let button, menu, evt;

function _buttonActivate() {
	Main.overview.hide();
	GLib.spawn_command_line_async("lxdm -c USER_SWITCH");
}

function init() {
}

function enable() {
	menu = Main.panel["statusArea"].userMenu;
	button = menu._loginScreenItem;
	evt=button.connect('activate', function(){GLib.spawn_command_line_async("lxdm -c USER_SWITCH");});
	button.actor.visible=true;
}

function disable() {
	if(evt && button)
		button.disconnect(evt);
	evt=undefined;
	button=undefined;
	menu=undefined;
}
