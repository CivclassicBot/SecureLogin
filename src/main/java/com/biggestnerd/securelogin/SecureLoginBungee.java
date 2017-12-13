package com.biggestnerd.securelogin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.UUID;
import java.util.logging.Level;

import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.ComponentBuilder;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.connection.PendingConnection;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.event.LoginEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.config.Configuration;
import net.md_5.bungee.config.ConfigurationProvider;
import net.md_5.bungee.config.YamlConfiguration;
import net.md_5.bungee.event.EventHandler;

public class SecureLoginBungee extends Plugin implements Listener {

	private SecureLoginHelper helper;
	
	public void onEnable() {
		Configuration config = loadConfig();
		Database db = loadDatabase(config.getSection("sql"));
		String denyMessage = config.getString("deny_message");
		int maxLength = config.getInt("max_length");
		int minLength = config.getInt("min_length");
		String host = config.getString("hostname");
		String charset = config.getString("charset");
		helper = new SecureLoginHelper(db, denyMessage, minLength, maxLength, host, charset);
		getProxy().getPluginManager().registerCommand(this, new SecureCommand());
		getProxy().getPluginManager().registerListener(this, this);
	}
	
	@EventHandler
	public void onLogin(PreLoginEvent event) {
		PendingConnection conn = event.getConnection();
		String prefix = conn.getVirtualHost().getHostString().split("\\.")[0];
		UUID id = conn.getUniqueId();
		System.out.println(String.format("[SecureLogin] prefix: %s, ip: %s, player: %s", prefix, conn.getVirtualHost().getHostString(), id));
		if(helper.getDatabase().shouldDenyAccess(id, prefix)) {
			conn.disconnect(new TextComponent(helper.getDenyMessage()));
		}
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
	
	class SecureCommand extends Command {

		public SecureCommand() {
			super("secure");
		}
		
		public void execute(CommandSender sender, String[] args) {
			if(!(sender instanceof ProxiedPlayer)) {
				sender.sendMessage(new ComponentBuilder("Only players can use /secure!").color(ChatColor.RED).create());
			} else {
				sender.sendMessage(new TextComponent(helper.executeCommand(((ProxiedPlayer)sender).getUniqueId(), args)));
			}
		}
	}
}
