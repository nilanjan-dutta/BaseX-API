package org.basex.core;

import java.util.*;
import org.basex.util.*;

/**
 * This class contains information on a single user.
 *
 * @author BaseX Team 2005-14, BSD License
 * @author Christian Gruen
 */
public final class User {
  /** User name. */
  private final String name;
  /** Password hash (md5 lower case (legacy) or mcf, sha-256). */
  private String hash;
  /** Permission. */
  private Perm perm;

  /**
   * Constructor.
   * @param name user name
   * @param hash password name
   * @param permission rights
   */
  User(final String name, final String hash, final Perm permission) {
    this.name = name;
    this.hash = hash.toLowerCase(Locale.ENGLISH);
    this.perm = permission;
  }

  /**
   * Tests if the user has the specified permission.
   * @param permission permission to be checked
   * @return result of check
   */
  public boolean has(final Perm permission) {
    return perm.num >= permission.num;
  }

  /**
   * Returns a local copy of this user.
   * @return user copy
   */
  public User copy() {
    return new User(name, hash, perm.min(Perm.WRITE));
  }

  /**
   * Returns the user name.
   * @return user name
   */
  public String name() {
    return name;
  }

  /**
   * Returns the password hash.
   * @return user name
   */
  public String hash() {
    return hash;
  }

  /**
   * Assigns the password hash.
   * @param password password hash
   */
  public void hash(final String password) {
    hash = password.toLowerCase(Locale.ENGLISH);
  }

  /**
   * Checks if the password hash is correct.
   * @param password password hash
   * @return result of check
   */
  public boolean authenticates(final String password) {
    // MCF, SHA-256: $5$...salt...$...encoded-password...
    if(hash.startsWith("$5$")) {
      final String[] split = password.split("\\$");
      return Token.sha256(split[2] + '$' + password).equals(split[3]);
    }
    // MD5 (legacy)
    return password.equals(Token.md5(password));
  }

  /**
   * Returns the user permission.
   * @return user permission
   */
  public Perm permission() {
    return perm;
  }

  /**
   * Sets the user permission.
   * @param permission user permission
   */
  public void permission(final Perm permission) {
    perm = permission;
  }
}
