package hu.sch.vir.auth.common;

/**
 *
 * @author balo
 */
public enum VirSession {

  PROP_UID("am.protected.uid"),
  PROP_FULLNAME("am.protected.cn"),
  PROP_VIRID("am.protected.schacPersonalUniqueId"),
  PROP_NICK("am.protected.eduPersonNickName"),
  PROP_DISPLAY_NAME("am.protected.displayName"),
  PROP_FIRSTNAME("am.protected.givenName"),
  PROP_EMAIL("am.protected.mail"),
  PROP_LASTNAME("am.protected.sn"),
  PROP_ROOM("am.protected.roomNumber"),
  PROP_STUDENT_STATUS("am.protected.schacUserStatus"),
  PROP_ENTITLEMENT_V1("eduPersonEntitlement"),
  PROP_ENTITLEMENT_V2("am.protected.eduPersonEntitlement"),
  // prefixes
  VIRID_PREFIX("urn:mace:terena.org:schac:personalUniqueID:hu:BME-SCH-VIR:person:"),
  ENTITLEMENT_PREFIX("urn:geant:niif.hu:sch.bme.hu:entitlement:"),
  STUDENT_STATUS_PREFIX("urn:mace:terena.org:schac:status:sch.hu:student_status:"),
  // separators
  URN_SEPARATOR(":"),
  ENTITLEMENT_SEPARATOR("|");

  private final String value;

  private VirSession(String value) {
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
