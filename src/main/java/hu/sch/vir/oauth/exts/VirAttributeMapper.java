package hu.sch.vir.oauth.exts;

import com.sun.identity.authentication.spi.AuthLoginException;
import hu.sch.vir.auth.common.ErrorCode;
import hu.sch.vir.auth.common.Helpers;
import hu.sch.vir.auth.common.VirDb;
import hu.sch.vir.auth.common.VirDbColumns;
import hu.sch.vir.auth.common.VirSession;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.forgerock.openam.authentication.modules.oauth2.AttributeMapper;
import org.forgerock.openam.authentication.modules.oauth2.OAuthUtil;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author balo
 */
public class VirAttributeMapper implements AttributeMapper {

  private static final String OAUTH_ATTR_LINKED_ACCOUNTS = "linkedAccounts";

  @Override
  public Map<String, Set<String>> getAttributes(Set<String> attributeMapConfiguration,
          String svcProfileResponse) throws AuthLoginException {

    OAuthUtil.debugMessage("virAttributeMapper.getAttributes: " + attributeMapConfiguration);

    final JSONObject json = getJsonResponse(svcProfileResponse);
    final Map<String, Set<String>> attr = new HashMap<>();
    attr.putAll(getAttributesFromConfig(attributeMapConfiguration, json));
    attr.putAll(getAttributesFromDb(json));

    return attr;
  }

  /**
   * Returns the received attributes mapped based on the "Attribute Mapper
   * Configuration" of the OAuth2 module.
   *
   * @param attributeMapConfiguration
   * @param svcProfileResponse
   * @return
   * @throws AuthLoginException
   */
  private Map<? extends String, ? extends Set<String>> getAttributesFromConfig(Set<String> attributeMapConfiguration,
          JSONObject json) throws AuthLoginException {

    final Map<String, Set<String>> attr = new HashMap<>();

    for (String entry : attributeMapConfiguration) {
      String responseName = "";

      try {
        if (!entry.contains("=")) {
          OAuthUtil.debugMessage("virAttributeMapper.getAttributes: Invalid entry." + entry);
          continue;
        }

        StringTokenizer st = new StringTokenizer(entry, "=");
        responseName = st.nextToken();
        String localName = st.nextToken();

        OAuthUtil.debugMessage("virAttributeMapper.getAttributes: "
                + responseName + ":" + localName);

        String data;
        if (responseName != null && responseName.contains(".")) {
          StringTokenizer parts = new StringTokenizer(responseName, ".");
          data = json.getJSONObject(parts.nextToken()).getString(parts.nextToken());
        } else {
          data = json.getString(responseName);
        }

        attr.put(localName, Helpers.asSet(data));
      } catch (JSONException ex) {
        OAuthUtil.debugError("virAttributeMapper.getAttributes: Could not "
                + "get the attribute: " + responseName, ex);
      }
    }

    return attr;
  }

  private JSONObject getJsonResponse(String responseObtained) throws AuthLoginException {
    JSONObject json;
    try {
      json = new JSONObject((String) responseObtained);
    } catch (JSONException ex) {
      OAuthUtil.debugError("OAuth.process(): JSONException: " + ex.getMessage());
      throw new AuthLoginException("VirAccountMapper: " + ex.getMessage());
    }

    return json;
  }

  private Map<? extends String, ? extends Set<String>> getAttributesFromDb(JSONObject json)
          throws AuthLoginException {

    final Map<String, Set<String>> attr = new HashMap<>();

    try {
      final JSONObject linkedAccounts = json.getJSONObject(OAUTH_ATTR_LINKED_ACCOUNTS);
      final String virUserName = linkedAccounts.getString("vir");

      try (VirDb virdb = new VirDb(virUserName, null)) {

        attr.put(VirSession.PROP_VIRID.val(),
                Helpers.asSet(virdb.getUserDataAsString(VirDbColumns.VIRID)));

        attr.put(VirSession.PROP_UID.val(),
                Helpers.asSet(virdb.getUserDataAsString(VirDbColumns.UID)));

        attr.put(VirSession.PROP_EMAIL.val(),
                Helpers.asSet(virdb.getUserDataAsString(VirDbColumns.EMAIL)));

        addIfExists(attr, VirSession.PROP_NICK,
                virdb.getUserDataAsString(VirDbColumns.NICK));

        addIfExists(attr, VirSession.PROP_STUDENT_STATUS,
                virdb.getUserDataAsString(VirDbColumns.STUDENT_STATUS));

        addIfExists(attr, VirSession.PROP_ROOM, getRoomString(virdb));

        final Set<String> entitlementAttr = Helpers.asSet(virdb.getEntitlementString());

        attr.put(VirSession.PROP_ENTITLEMENT_V1.val(), entitlementAttr);
        attr.put(VirSession.PROP_ENTITLEMENT_V2.val(), entitlementAttr);

      } catch (AuthLoginException ex) {
        if (ErrorCode.NULL_RESULT.toString().equalsIgnoreCase(ex.getErrorCode())) {
          //no vir user
        } else {
          throw new AuthLoginException(ex);
        }
      }

    } catch (JSONException ex) {
      OAuthUtil.debugError("virAttributeMapper.getAttributes: Could not "
              + "process the attribute: " + OAUTH_ATTR_LINKED_ACCOUNTS, ex);
    }

    return attr;
  }

  private String getRoomString(final VirDb virdb) {
    final String dorm = virdb.getUserDataAsString(VirDbColumns.DORM);
    final String room = virdb.getUserDataAsString(VirDbColumns.ROOM);
    final String dormAndRoom = dorm == null || dorm.isEmpty() ? "" : dorm + " " + room;

    return dormAndRoom;
  }

  private void addIfExists(Map<String, Set<String>> attr, VirSession key, String value) {
    if (value != null && !value.isEmpty()) {
      attr.put(key.val(), Helpers.asSet(value));
    }
  }

}
