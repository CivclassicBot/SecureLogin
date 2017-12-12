package com.biggestnerd.securelogin;

import java.util.Random;
import java.util.UUID;

import org.apache.commons.lang3.RandomStringUtils;

import net.md_5.bungee.api.ChatColor;

public class SecureLoginHelper {
	
	private Database db;
	private Random rng = new Random();
	private String denyMessage;
	private int minLength;
	private int maxLength;
	private String host;
	private char[] charset;
	
	public SecureLoginHelper(Database db, String denyMessage, int minLength, int maxLength, String host, String charset) {
		this.db = db;
		this.denyMessage = denyMessage;
		this.minLength = minLength;
		this.maxLength = maxLength;
		this.host = host;
		this.charset = charset.toCharArray();
	}

	public String executeCommand(UUID player, String[] args) {
		if(args.length != 0) {
			if(args[0].equals("revoke")) {
				db.revokeToken(player);
				return ChatColor.GREEN + "Your secure login has been revoked";
			}
		} else if(db.getPrefix(player) != null) {
			return ChatColor.RED + "You already have a secure login, message modmail if you think this is a mistake.";
		} else {
			String token = generateSecureToken();
			db.setPrefix(player, token);
			return ChatColor.GOLD + "Your new secure login is " + token + "." + host;
		}
		return ChatColor.RED + "Invalid arguments, see /help secure";
	}
	
	public String getDenyMessage() {
		return denyMessage;
	}
	
	public Database getDatabase() {
		return db;
	}
	
	private String generateSecureToken() {
		StringBuilder tokenBuilder = new StringBuilder();
		int length = minLength + rng.nextInt(maxLength - minLength + 1);
		for(int i = 0; i < length; i++) {
			tokenBuilder.append(charset[rng.nextInt(charset.length)]);
		}
		return tokenBuilder.toString();
	}
}
