package org.basex.query.func.map;

import org.basex.query.*;
import org.basex.query.func.*;
import org.basex.query.value.item.*;
import org.basex.query.value.map.*;
import org.basex.util.*;

/**
 * Function implementation.
 *
 * @author BaseX Team 2005-14, BSD License
 * @author Leo Woerteler
 */
public class MapEntry extends StandardFunc {
  @Override
  public final Item item(final QueryContext qc, final InputInfo ii) throws QueryException {
    return Map.EMPTY.insert(toAtomItem(exprs[0], qc), qc.value(exprs[1]), ii);
  }
}
