package com.biggestnerd.securelogin;

import java.net.InetAddress;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.logging.Level;

import org.apache.commons.lang3.RandomStringUtils;
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
	private Random rng;
	private String denyMessage;
	private int minLength;
	private int maxLength;
	private String host;
	
	private boolean bungee = false;
	
	private Database db;
	
	@Override
	public void onEnable() {
		rng = new Random();
		prefixMap = new HashMap<InetAddress, String>();
		loadConfig();
		setupDatabase();
		if(getServer().getPluginManager().isPluginEnabled(this) && getServer().getPluginManager().isPluginEnabled("ProtocolLib") && !bungee) {
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
			if(db.shouldDenyAccess(id, prefix)) {
				event.disallow(Result.KICK_OTHER, denyMessage);
			}
		}
	}
	
	@Override
	public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
		if(!(sender instanceof Player)) {
			sender.sendMessage(ChatColor.RED + "Cant get a secure login for you console connection idiot.");
		} else {
			Player player = (Player) sender;
			if(args.length != 0) {
				if(args[0].equals("revoke")) {
					db.revokeToken(player.getUniqueId());
					player.sendMessage(ChatColor.GREEN + "Your secure login has been revoked");
				}
			} else if(db.getPrefix(player.getUniqueId()) != null) {
				player.sendMessage(ChatColor.RED + "You already have a secure login, message modmail if you think this is a mistake.");
			} else {
				String token = generateSecureToken();
				db.setPrefix(player.getUniqueId(), token);
				player.sendMessage(ChatColor.GOLD + "Your new secure login is " + token + "." + host);
			}
		}
		return true;
	}
	
	private String generateSecureToken() {
		return RandomStringUtils.randomAlphanumeric(minLength + rng.nextInt(maxLength - minLength + 1));
	}
	
	private void loadConfig() {
		saveDefaultConfig();
		reloadConfig();
		FileConfiguration config = getConfig();
		bungee = config.getBoolean("bungee");
		denyMessage = config.getString("deny_message");
		minLength = config.getInt("min_length");
		maxLength = Math.min(config.getInt("max_length"), 40);
		host = config.getString("hostname");
	}
	
	private void setupDatabase() {
		ConfigurationSection config = getConfig().getConfigurationSection("sql");
		String host = config.getString("host");
		int port = config.getInt("port");
		String user = config.getString("user");
		String pass = config.getString("password");
		String dbname = config.getString("database");
		int poolsize = config.getInt("poolsize");
		long connectionTimeout = config.getLong("connectionTimeout");
		long idleTimeout = config.getLong("idleTimeout");
		long maxLifetime = config.getLong("maxLifetime");
		db = new Database(getLogger(), user, pass, host, port, dbname, poolsize, connectionTimeout, idleTimeout, maxLifetime);
		try {
			db.getConnection().close();
		} catch (SQLException e) {
			getLogger().log(Level.WARNING, "Failed to connect to database, shutting down", e);
			getServer().getPluginManager().disablePlugin(this);
		}
	}
 }