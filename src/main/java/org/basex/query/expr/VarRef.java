package org.basex.query.expr;

import static org.basex.query.QueryTokens.*;
import static org.basex.util.Token.*;
import java.io.IOException;
import org.basex.data.Serializer;
import org.basex.query.QueryContext;
import org.basex.query.QueryException;
import org.basex.query.item.QNm;
import org.basex.query.item.Uri;
import org.basex.query.iter.Iter;
import org.basex.query.util.Namespaces;
import org.basex.query.util.Var;
import org.basex.util.InputInfo;
import org.basex.util.TokenBuilder;

/**
 * Variable Reference expression.
 *
 * @author Workgroup DBIS, University of Konstanz 2005-10, ISC License
 * @author Christian Gruen
 */
public final class VarRef extends ParseExpr {
  /** Variable name. */
  Var var;

  /**
   * Constructor.
   * @param ii input info
   * @param v variable
   */
  public VarRef(final InputInfo ii, final Var v) {
    super(ii);
    var = v;
  }

  @Override
  public Expr comp(final QueryContext ctx) throws QueryException {
    var = ctx.vars.get(var);
    type = var.type();

    // return if variable expression has not yet been assigned
    Expr e = var.expr();
    if(e == null) return this;

    // pre-assign static variables
    final Namespaces lc = ctx.ns;
    ctx.ns = lc.copy();
    if(ctx.nsElem.length != 0)
      ctx.ns.add(new QNm(EMPTY, Uri.uri(ctx.nsElem)), input);

    /* Choose variables to be pre-evaluated.
     * If a variable is pre-evaluated, it may not be available for further
     * optimizations (index access, count, ...). On the other hand, multiple
     * evaluations of the same expression are avoided. */
    if(var.global || ctx.nsElem.length != 0 || lc.size() != 0 ||
        var.type != null || e.uses(Use.FRG) || e instanceof FuncCall) {
      e = var.value(ctx);
    }

    ctx.ns = lc;
    return e;
  }

  @Override
  public Iter iter(final QueryContext ctx) throws QueryException {
    var = ctx.vars.get(var);
    return ctx.iter(var);
  }

  @Override
  public boolean uses(final Use u) {
    // [CG] XQuery/flags: check flags (FRG?)
    return u == Use.VAR || u != Use.CTX &&
      var.expr() != null && var.expr().uses(u);
  }

  @Override
  public boolean removable(final Var v) {
    return true;
  }

  @Override
  public Expr remove(final Var v) {
    return var.eq(v) ? new Context(input) : this;
  }

  @Override
  public void plan(final Serializer ser) throws IOException {
    ser.emptyElement(this, NAM, token(var.toString()));
  }

  @Override
  public String desc() {
    return VARBL;
  }

  @Override
  public String toString() {
    return new TokenBuilder(DOLLAR).add(var.name.atom()).toString();
  }
}