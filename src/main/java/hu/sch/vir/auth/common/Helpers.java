package hu.sch.vir.auth.common;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author balo
 */
public class Helpers {

  /**
   * Creates an <i>immutable</i> {@code HashSet} instance containing the given
   * elements in unspecified order.
   *
   * @param <E>
   * @param elements the elements that the set should contain
   * @return a new {@code HashSet} containing those elements (minus
   * duplicates)
   */
  public static <E> Set asSet(final E... elements) {
    if (elements == null) {
      return new HashSet<>(0);
    }
    final Set<E> set = new HashSet<>(elements.length);
    Collections.addAll(set, elements);
    return Collections.unmodifiableSet(set);
  }

}
