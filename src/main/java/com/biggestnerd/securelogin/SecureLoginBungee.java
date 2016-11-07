package com.biggestnerd.securelogin;

import java.util.UUID;

import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;

public class SecureLoginBungee extends Plugin implements Listener {
	
	private SecureLogin plugin;
	
	@Override
	public void onEnable() {
		plugin = SecureLogin.instance();
		getProxy().getPluginManager().registerListener(this, this);
	}
	
	@EventHandler
	public void onLogin(LoginEvent event) {
		UUID player = event.getConnection().getUniqueId();
		String prefix = event.getConnection().getVirtualHost().getHostString().split(".\\")[0];
		if(plugin.shouldDenyAccess(player, prefix)) {
			event.setCancelReason(SecureLogin.instance().getDenialMessage());
			event.setCancelled(true);
		}
	}
}