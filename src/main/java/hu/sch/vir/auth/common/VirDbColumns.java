package hu.sch.vir.auth.common;

/**
 *
 * @author balo
 */
public enum VirDbColumns {

  //membership columns
  GROUP_ID("grp_id"),
  GROUP_NAME("grp_name"),
  POST_NAME("pttip_name"),
  //user columns
  VIRID("usr_id"),
  UID("usr_screen_name"),
  PW_SALT("usr_salt"),
  FIRSTNAME("usr_firstname"),
  STUDENT_STATUS("usr_student_status"),
  NICK("usr_nickname"),
  PASSWORD("usr_password"),
  LASTNAME("usr_lastname"),
  EMAIL("usr_email"),
  DORM("usr_dormitory"),
  ROOM("usr_room");

  private final String value;

  private VirDbColumns(String value) {
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
