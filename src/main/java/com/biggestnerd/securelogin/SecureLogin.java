package com.biggestnerd.securelogin;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.InetAddress;
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
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

public class SecureLogin extends JavaPlugin implements Listener, CommandExecutor {

	private Map<UUID, String> prefixes;
	private Map<InetAddress, String> prefixMap;
	private Random rng;
	private String denyMessage;
	private File prefixFile;
	private int minLength;
	private int maxLength;
	private String host;
	
	@Override
	public void onEnable() {
		rng = new Random();
		prefixMap = new HashMap<InetAddress, String>();
		loadConfig();
		prefixes = loadPrefixes();
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
	
	@EventHandler
	public void onAsyncPlayerPreLogin(AsyncPlayerPreLoginEvent event) {
		UUID id = event.getUniqueId();
		if(!prefixes.containsKey(event.getUniqueId())) {
			getLogger().info(id + " not using secure login.");
			return;
		}
		if(prefixMap.containsKey(event.getAddress())) {
			getLogger().info(event.getUniqueId() + " checking secure login id.");
			String prefix = prefixMap.get(event.getAddress());
			if(!prefixes.get(event.getUniqueId()).equals(prefix)) {
				getLogger().info(event.getUniqueId() + " denied login, wrong login id.");
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
					prefixes.remove(player.getUniqueId());
					savePrefixes();
					player.sendMessage(ChatColor.GREEN + "Your secure login has been revoked");
				} else if(args[0].equals("reload") && player.hasPermission("securedomain.admin")) {
					prefixes = loadPrefixes();
					player.sendMessage(ChatColor.GREEN + "Prefixes reloaded");
				}
			} else if(prefixes.containsKey(player.getUniqueId())) {
				player.sendMessage(ChatColor.RED + "You already have a secure login, message modmail if you think this is a mistake.");
			} else {
				String token = generateSecureToken();
				prefixes.put(player.getUniqueId(), token);
				player.sendMessage(ChatColor.GOLD + "Your new secure login is " + token + "." + host);
				savePrefixes();
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
		denyMessage = config.getString("deny_message");
		prefixFile = new File(getDataFolder(), config.getString("save_file_name"));
		if(!prefixFile.exists()) {
			try {
				prefixFile.createNewFile();
			} catch (IOException e) {
				getLogger().log(Level.SEVERE, "Could not create prefix file, shutting down: ", e);
				getServer().getPluginManager().disablePlugin(this);
			}
		}
		minLength = config.getInt("min_length");
		maxLength = config.getInt("max_length");
		host = config.getString("hostname");
	}
	
	private Map<UUID, String> loadPrefixes() {
		try {
			Gson gson = new Gson();
			Type type = new TypeToken<HashMap<UUID, String>>(){}.getType();
			Map<UUID, String> map = gson.fromJson(new FileReader(prefixFile), type);
			return map != null ? map : new HashMap<UUID, String>();
		} catch (Exception ex) {
			getLogger().log(Level.SEVERE, "Error loading prefixes: ", ex);
			return new HashMap<UUID, String>();
		}
	}
	
	private void savePrefixes() {
		try {
			Gson gson = new GsonBuilder().setPrettyPrinting().create();
			String json = gson.toJson(prefixes);
			FileWriter writer = new FileWriter(prefixFile);
			writer.write(json);
			writer.close();
		} catch (Exception ex) {
			getLogger().log(Level.SEVERE, "Error saving prefixes: ", ex);
		}
	}
 }
