package org.basex.query.func.html;

import static org.basex.query.QueryText.*;
import static org.basex.query.util.Err.*;

import java.io.*;

import org.basex.build.*;
import org.basex.io.*;
import org.basex.query.*;
import org.basex.query.func.*;
import org.basex.query.value.item.*;
import org.basex.query.value.node.*;
import org.basex.util.*;

/**
 * Function implementation.
 *
 * @author BaseX Team 2005-14, BSD License
 * @author Christian Gruen
 */
public final class HtmlParse extends StandardFunc {
  /** QName. */
  private static final QNm Q_OPTIONS = QNm.get("options", HTML_URI);

  @Override
  public Item item(final QueryContext qc, final InputInfo ii) throws QueryException {
    final byte[] in = toBinary(exprs[0], qc);
    final HtmlOptions opts = toOptions(1, Q_OPTIONS, new HtmlOptions(), qc);
    try {
      final Parser p = new org.basex.build.HtmlParser(new IOContent(in), qc.context.options, opts);
      return new DBNode(p);
    } catch(final IOException ex) {
      throw BXHL_IO_X.get(info, ex);
    }
  }
}
