package com.biggestnerd.securelogin;

import java.net.InetAddress;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;

import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result;
import org.bukkit.plugin.java.JavaPlugin;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketEvent;

public class SecureLoginBukkit extends JavaPlugin implements Listener, CommandExecutor {

	private Map<InetAddress, String> prefixMap;
	
	private SecureLoginHelper helper;
	
	@Override
	public void onEnable() {
		prefixMap = new HashMap<InetAddress, String>();
		saveDefaultConfig();
		reloadConfig();
		FileConfiguration config = getConfig();
		String denyMessage = config.getString("deny_message");
		int minLength = config.getInt("min_length");
		int maxLength = Math.min(config.getInt("max_length"), 40);
		String host = config.getString("hostname");
		String charset = config.getString("charset");
		Database db = setupDatabase(config.getConfigurationSection("sql"));
		helper = new SecureLoginHelper(db, denyMessage, minLength, maxLength, host, charset);
		if(getServer().getPluginManager().isPluginEnabled(this) && getServer().getPluginManager().isPluginEnabled("ProtocolLib")) {
			ProtocolLibrary.getProtocolManager().addPacketListener(
				new PacketAdapter(this, ListenerPriority.HIGHEST, PacketType.Handshake.Client.SET_PROTOCOL) {
					@Override
					public void onPacketReceiving(PacketEvent event) {
						String host = event.getPacket().getStrings().read(0);
						String prefix = host.split("\\.")[0];
						prefixMap.put(event.getPlayer().getAddress().getAddress(), prefix);
					}
				});
			getServer().getPluginManager().registerEvents(this, this);
		}
	}
	
	@EventHandler
	public void onAsyncPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
		UUID id = event.getUniqueId();
		InetAddress address = event.getAddress();
		if(prefixMap.containsKey(address)) {
			String prefix = prefixMap.get(address);
			if(helper.getDatabase().shouldDenyAccess(id, prefix)) {
				event.disallow(Result.KICK_OTHER, helper.getDenyMessage());
			}
		} else if(helper.getDatabase().getPrefix(id) != null) {
			event.disallow(Result.KICK_OTHER, helper.getDenyMessage());
		}
	}
	
	@Override
	public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
		if(!(sender instanceof Player)) {
			sender.sendMessage(ChatColor.RED + "Cant get a secure login for you console connection idiot.");
		} else {
			sender.sendMessage(helper.executeCommand(((Player)sender).getUniqueId(), args));
		}
		return true;
	}
	
	private Database setupDatabase(ConfigurationSection config) {
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
			getServer().getPluginManager().disablePlugin(this);
		}
		return db;
	}
 }