package com.biggestnerd.securelogin;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

public class Database {
	public static final String INIT_DB = 
			"create table if not exists login_prefix("
			+ "player varchar(40) unique not null,"
			+ "token varchar(40) not null);";

	private HikariDataSource datasource;
	private Logger log;
	
	public Database(Logger log, String user, String pass, String host, int port, String database,
			int poolSize, long connectionTimeout, long idleTimeout, long maxLifetime) {
		this.log = log;
		if (user != null && host != null && port > 0 && database != null) {
			HikariConfig config = new HikariConfig();
			config.setJdbcUrl("jdbc:mysql://" + host + ":" + port + "/" + database);
			config.setConnectionTimeout(connectionTimeout); // 1000l);
			config.setIdleTimeout(idleTimeout); //600000l);
			config.setMaxLifetime(maxLifetime); //7200000l);
			config.setMaximumPoolSize(poolSize); //10);
			config.setUsername(user);
			if (pass != null) {
				config.setPassword(pass);
			}
			this.datasource = new HikariDataSource(config);
			
			try {
				Connection connection = getConnection();
				PreparedStatement statement = connection.prepareStatement(Database.INIT_DB);
				statement.execute();
				statement.close();
				connection.close();
			} catch (SQLException se) {
				log.log(Level.SEVERE, "Unable to initialize Database", se);
				this.datasource = null;
			}
		} else {
			this.datasource = null;
			log.log(Level.SEVERE, "Database not configured and is unavaiable");
		}
	}
	
	public Connection getConnection() throws SQLException {
		available();
		return datasource.getConnection();
	}
	
	public void close() throws SQLException {
		available();
		datasource.close();
	}
	
	public void available() throws SQLException {
		if(datasource == null) {
			throw new SQLException("No Datasource Available");
		}
	}
	
	public String getPrefix(UUID id) {
		try (Connection conn = getConnection();
				PreparedStatement ps = conn.prepareStatement("select * from login_prefix where player=?;")) {
			ps.setString(1, id.toString());
			ResultSet res = ps.executeQuery();
			if(res.next()) {
				return res.getString("token");
			}
		} catch (SQLException e) {
			log.log(Level.WARNING, "Failed to retrieve prefix for " + id, e);
		}
		return null;
	}
	
	public void setPrefix(UUID id, String token) {
		if(getPrefix(id) != null) return;
		try (Connection conn = getConnection();
				PreparedStatement ps = conn.prepareStatement("insert into login_prefix (player, token) values (?,?);")) {
			ps.setString(1, id.toString());
			ps.setString(2, token);
			ps.executeUpdate();
		} catch (SQLException e) {
			log.log(Level.WARNING, "Failed to set prefix for " + id, e);
		}
	}
	
	public void revokeToken(UUID id) {
		try (Connection conn = getConnection();
				PreparedStatement ps = conn.prepareStatement("delete from login_prefix where player=?;")) {
			ps.setString(1, id.toString());
			ps.executeUpdate();
		} catch (SQLException e) {
			log.log(Level.WARNING, "Failed to delete prefix for " + id, e);
		}
	}
	
	/**
	 * @param player the player trying to connect
	 * @param prefix the prefix they logged in with
	 * @return whether or not they used the right prefix
	 */
	public boolean shouldDenyAccess(UUID player, String prefix) {
		String token = getPrefix(player);
		return token != null && !token.equals(prefix);
	}
}
