package hu.sch.vir.auth.common;

/**
 *
 * @author balo
 */
public enum Queries {

  GET_USER_DATA_STMT("select usr_password,usr_salt, "
          + "usr_id, usr_email, usr_firstname, usr_lastname, usr_nickname, "
          + "usr_screen_name, usr_dormitory, usr_room, usr_student_status "
          + "from users where LOWER(usr_screen_name) = ?"),
  //
  UPDATE_LASTLOGIN_STMT("UPDATE users " + "SET usr_lastlogin=NOW() " + "WHERE usr_id = ?"),
  //
  MEMBERSHIPS_STMT("SELECT grp_membership.grp_id, groups.grp_name, poszttipus.pttip_name "
          + "FROM grp_membership JOIN groups USING (grp_id) "
          + "JOIN poszt ON poszt.grp_member_id = grp_membership.id "
          + "JOIN poszttipus ON poszt.pttip_id = poszttipus.pttip_id "
          + "WHERE (grp_membership.usr_id=? AND membership_end is null) "
          + "UNION "
          + "(SELECT grp_membership.grp_id, groups.grp_name, 'tag' AS pttip_name "
          + "FROM grp_membership JOIN groups USING (grp_id) "
          + "LEFT OUTER JOIN poszt ON poszt.grp_member_id = grp_membership.id "
          + "WHERE (poszt.pttip_id <> 6 OR poszt.pttip_id IS null) "
          + "AND usr_id = ? AND grp_membership.membership_end IS null) "
          + "ORDER BY grp_id");

  private final String value;

  private Queries(String value) {
    this.value = value;
  }

  public String val() {
    return value;
  }

  @Override
  public String toString() {
    return value;
  }

}
