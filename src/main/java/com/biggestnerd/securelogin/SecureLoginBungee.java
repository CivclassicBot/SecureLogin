package com.biggestnerd.securelogin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.UUID;
import java.util.logging.Level;

import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;

public class SecureLoginBungee extends Plugin implements Listener {

	private Database db;
	
	public void onEnable() {
		Configuration config = loadConfig();
		if(config != null) {
			db = loadDatabase(config.getSection("sql"));
		}
		if(db != null) {
			getProxy().getPluginManager().registerListener(this, this);
		}
	}
	
	@EventHandler
	public void onLogin(LoginEvent event) {
		PendingConnection conn = event.getConnection();
		String prefix = conn.getVirtualHost().getHostString().split("\\.")[0];
		UUID id = conn.getUniqueId();
		event.setCancelled(db.shouldDenyAccess(id, prefix));
	}
	
	private Configuration loadConfig() {
		if(!getDataFolder().exists()) {
			getDataFolder().mkdirs();
		}
		
		File file = new File(getDataFolder(), "config.yml");
		
		if(!file.exists()) {
			try (InputStream in = getResourceAsStream("config.yml")) {
				Files.copy(in, file.toPath());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		try {
			return ConfigurationProvider.getProvider(YamlConfiguration.class).load(file);
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private Database loadDatabase(Configuration config) {
		String host = config.getString("host");
		int port = config.getInt("port");
		String user = config.getString("user");
		String pass = config.getString("password");
		String dbname = config.getString("database");
		int poolsize = config.getInt("poolsize");
		long connectionTimeout = config.getLong("connectionTimeout");
		long idleTimeout = config.getLong("idleTimeout");
		long maxLifetime = config.getLong("maxLifetime");
		Database db = new Database(getLogger(), user, pass, host, port, dbname, poolsize, connectionTimeout, idleTimeout, maxLifetime);
		try {
			db.getConnection().close();
		} catch (SQLException e) {
			getLogger().log(Level.WARNING, "Failed to connect to database, shutting down", e);
			return null;
		}
		return db;
	}
}
