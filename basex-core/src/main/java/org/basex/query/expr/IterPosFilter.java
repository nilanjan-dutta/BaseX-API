package org.basex.query.expr;

import org.basex.query.*;
import org.basex.query.iter.*;
import org.basex.query.value.item.*;
import org.basex.query.var.*;
import org.basex.util.*;
import org.basex.util.hash.*;

/**
 * Iterative filter expression with numeric predicates.
 *
 * @author BaseX Team 2005-14, BSD License
 * @author Christian Gruen
 */
final class IterPosFilter extends Filter {
  /** Offset flag. */
  private final boolean off;

  /**
   * Constructor.
   * @param info input info
   * @param off offset flag
   * @param root root expression
   * @param preds predicates
   */
  IterPosFilter(final InputInfo info, final boolean off, final Expr root, final Expr... preds) {
    super(info, root, preds);
    this.off = off;
  }

  @Override
  public Iter iter(final QueryContext qc) {
    return new Iter() {
      boolean skip, direct;
      Iter iter;
      long cpos;

      @Override
      public Item next() throws QueryException {
        if(skip) return null;

        // first call - initialize iterator
        if(iter == null) {
          if(off) {
            // evaluate offset and create position expression
            final Item it = preds[0].ebv(qc, info);
            final long l = it.itr(info);
            final Expr e = Pos.get(l, l, info);
            // don't accept fractional numbers
            if(l != it.dbl(info) || !(e instanceof Pos)) return null;
            pos = (Pos) e;
          }

          iter = qc.iter(root);
          cpos = 1;

          if(pos != null || last) {
            // runtime optimization:
            // items can be directly accessed if the iterator size is known
            final long s = iter.size();
            if(s == 0) return null;
            if(s != -1) {
              cpos = last ? s : pos.min;
              if(cpos > s) return null;
              direct = preds.length == 1;
            }
          }
        }

        // cache context
        final long cp = qc.pos;
        final long cs = qc.size;
        try {
          Item item;
          if(direct) {
            // directly access relevant items
            item = iter.size() < cpos ? null : iter.get(cpos - 1);
            qc.pos = cpos++;
          } else {
            // loop through all items
            Item lnode = null;
            while((item = iter.next()) != null) {
              // evaluate predicates
              qc.checkStop();
              qc.size = 0;
              qc.pos = cpos++;
              if(preds(item, qc)) break;
              // remember last node
              lnode = item;
              qc.pos = cp;
              qc.size = cs;
            }
            // returns the last item
            if(last) item = lnode;
          }

          // check if more items can be expected
          skip = last || pos != null && pos.skip(qc);
          return item;
        } finally {
          // reset context and return result
          qc.pos = cp;
          qc.size = cs;
        }
      }
    };
  }

  @Override
  public IterPosFilter copy(final QueryContext qc, final VarScope scp, final IntObjMap<Var> vs) {
    return copy(new IterPosFilter(info, off, root.copy(qc, scp, vs),
        Arr.copyAll(qc, scp, vs, preds)));
  }
}
