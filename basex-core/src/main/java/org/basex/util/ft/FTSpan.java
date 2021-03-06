package org.basex.util.ft;

import static org.basex.util.Token.*;

import org.basex.util.*;

/**
 * This class contains a single full-text token.
 *
 * @author BaseX Team 2005-14, BSD License
 * @author Jens Erat
 */
public final class FTSpan {
  /** Text. */
  public byte[] text;
  /** Token position. */
  public final int pos;
  /** Special character flag. */
  public final boolean special;

  /**
   * Constructor.
   * @param text token text
   * @param pos number of tokens parsed before the current token
   * @param special is a special character
   */
  FTSpan(final byte[] text, final int pos, final boolean special) {
    this.text = text;
    this.pos = pos;
    this.special = special;
  }

  @Override
  public String toString() {
    return Util.className(this) + '[' + string(text) + ']';
  }
}
